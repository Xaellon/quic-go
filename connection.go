package quic

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

type unpacker interface {
	UnpackLongHeader(hdr *wire.Header, data []byte) (*unpackedPacket, error)
	UnpackShortHeader(rcvTime monotime.Time, data []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error)
}

type cryptoStreamHandler interface {
	StartHandshake(context.Context) error
	ChangeConnectionID(protocol.ConnectionID)
	SetLargest1RTTAcked(protocol.PacketNumber) error
	SetHandshakeConfirmed()
	GetSessionTicket() ([]byte, error)
	NextEvent() handshake.Event
	DiscardInitialKeys()
	HandleMessage([]byte, protocol.EncryptionLevel) error
	io.Closer
	ConnectionState() handshake.ConnectionState
}

type receivedPacket struct {
	buffer *packetBuffer

	remoteAddr net.Addr
	rcvTime    monotime.Time
	data       []byte

	ecn protocol.ECN

	info packetInfo
}

type receivedPacketWithChecksum struct {
	receivedPacket
	checksum qlog.DatagramPayloadChecksum
}

func (p *receivedPacket) Size() protocol.ByteCount { return protocol.ByteCount(len(p.data)) }

func (p *receivedPacket) Clone() *receivedPacket {
	return &receivedPacket{
		remoteAddr: p.remoteAddr,
		rcvTime:    p.rcvTime,
		data:       p.data,
		buffer:     p.buffer,
		ecn:        p.ecn,
		info:       p.info,
	}
}

// A pathReceiver is the packetHandler that a connection registers on every Transport it uses:
// the one it was dialed or accepted on, and the ones added via AddPath.
// It allows the connection to tell which Transport a packet was received on.
type pathReceiver struct {
	*Conn
	id pathID // the ID of the first path that used the Transport, also used as its qlog TupleID
}

var _ packetHandler = &pathReceiver{}

func (r *pathReceiver) handlePacket(p receivedPacket) { r.queuePacket(p, r) }

type connRunner interface {
	Add(protocol.ConnectionID, packetHandler) bool
	Remove(protocol.ConnectionID)
	ReplaceWithClosed([]protocol.ConnectionID, []byte, time.Duration)
	AddResetToken(protocol.StatelessResetToken, packetHandler)
	RemoveResetToken(protocol.StatelessResetToken)
}

type closeError struct {
	err       error
	immediate bool
}

type errCloseForRecreating struct {
	nextPacketNumber protocol.PacketNumber
	nextVersion      protocol.Version
}

func (e *errCloseForRecreating) Error() string {
	return "closing connection in order to recreate it"
}

var deadlineSendImmediately = monotime.Time(42 * time.Millisecond)

type blockMode uint8

const (
	blockModeNone blockMode = iota

	blockModeCongestionLimited

	blockModeHardBlocked
)

type Conn struct {
	handshakeDestConnID protocol.ConnectionID

	origDestConnID protocol.ConnectionID
	retrySrcConnID *protocol.ConnectionID

	srcConnIDLen int

	perspective protocol.Perspective
	version     protocol.Version
	config      *Config

	conn      sendConn
	sendQueue sender

	pathManager         *pathManager
	largestRcvdAppData  protocol.PacketNumber
	pathManagerOutgoing atomic.Pointer[pathManagerOutgoing]

	streamsMap      *streamsMap
	connIDManager   *connIDManager
	connIDGenerator *connIDGenerator

	rttStats  *utils.RTTStats
	connStats utils.ConnectionStats

	cryptoStreamManager   *cryptoStreamManager
	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler
	retransmissionQueue   *retransmissionQueue
	framer                *framer
	connFlowController    *connectionFlowController
	tokenStoreKey         string
	tokenGenerator        *handshake.TokenGenerator

	unpacker      unpacker
	frameParser   wire.FrameParser
	packer        packer
	mtuDiscoverer *mtuFinder

	maxPayloadSizeEstimate atomic.Uint32

	initialStream       *initialCryptoStream
	handshakeStream     *cryptoStream
	oneRTTStream        *cryptoStream
	cryptoStreamHandler cryptoStreamHandler

	notifyReceivedPacket chan struct{}
	sendingScheduled     chan struct{}
	receivedPackets      receivedPacketQueue

	closeChan chan struct{}
	closeErr  atomic.Pointer[closeError]

	ctx                   context.Context
	ctxCancel             context.CancelCauseFunc
	handshakeCompleteChan chan struct{}

	undecryptablePackets          []receivedPacketWithChecksum
	undecryptablePacketsToProcess []receivedPacketWithChecksum

	earlyConnReadyChan chan struct{}
	sentFirstPacket    bool
	droppedInitialKeys bool
	handshakeComplete  bool
	handshakeConfirmed bool

	receivedRetry       bool
	versionNegotiated   bool
	receivedFirstPacket bool

	blocked blockMode

	idleTimeout  time.Duration
	creationTime monotime.Time

	lastPacketReceivedTime monotime.Time

	firstAckElicitingPacketAfterIdleSentTime monotime.Time

	pacingDeadline monotime.Time

	peerParams *wire.TransportParameters

	timer *time.Timer

	keepAlivePingSent bool
	keepAliveInterval time.Duration

	datagramQueue *datagramQueue

	connStateMutex sync.Mutex
	connState      ConnectionState

	logID     string
	qlogTrace qlogwriter.Trace
	qlogger   qlogwriter.Recorder
	logger    utils.Logger
}

var _ streamSender = &Conn{}

type connTestHooks struct {
	run                     func() error
	earlyConnReady          func() <-chan struct{}
	context                 func() context.Context
	handshakeComplete       func() <-chan struct{}
	closeWithTransportError func(TransportErrorCode)
	destroy                 func(error)
	handlePacket            func(receivedPacket)
}

type wrappedConn struct {
	testHooks    *connTestHooks
	pathReceiver // for the Transport that the connection was dialed or accepted on
}

var newConnection = func(
	ctx context.Context,
	ctxCancel context.CancelCauseFunc,
	conn sendConn,
	runner connRunner,
	origDestConnID protocol.ConnectionID,
	retrySrcConnID *protocol.ConnectionID,
	clientDestConnID protocol.ConnectionID,
	destConnID protocol.ConnectionID,
	srcConnID protocol.ConnectionID,
	connIDGenerator ConnectionIDGenerator,
	statelessResetter *statelessResetter,
	conf *Config,
	tlsConf *tls.Config,
	tokenGenerator *handshake.TokenGenerator,
	clientAddressValidated bool,
	rtt time.Duration,
	qlogTrace qlogwriter.Trace,
	logger utils.Logger,
	v protocol.Version,
) *wrappedConn {
	s := &Conn{
		ctx:                 ctx,
		ctxCancel:           ctxCancel,
		conn:                conn,
		config:              conf,
		handshakeDestConnID: destConnID,
		srcConnIDLen:        srcConnID.Len(),
		tokenGenerator:      tokenGenerator,
		oneRTTStream:        newCryptoStream(),
		perspective:         protocol.PerspectiveServer,
		qlogTrace:           qlogTrace,
		logger:              logger,
		version:             v,
	}
	w := &wrappedConn{pathReceiver: pathReceiver{Conn: s}}
	if qlogTrace != nil {
		s.qlogger = qlogTrace.AddProducer()
	}
	if origDestConnID.Len() > 0 {
		s.logID = origDestConnID.String()
	} else {
		s.logID = destConnID.String()
	}
	s.connIDManager = newConnIDManager(
		destConnID,
		func(token protocol.StatelessResetToken) { runner.AddResetToken(token, &w.pathReceiver) },
		runner.RemoveResetToken,
		s.queueControlFrame,
	)
	s.connIDGenerator = newConnIDGenerator(
		runner,
		srcConnID,
		&clientDestConnID,
		statelessResetter,
		&w.pathReceiver,
		s.queueControlFrame,
		connIDGenerator,
	)
	s.preSetup(&w.pathReceiver)
	s.rttStats.SetInitialRTT(rtt)
	s.sentPacketHandler = ackhandler.NewSentPacketHandlerWithPacingRate(
		0,
		s.config.initialPacketSize(),
		s.rttStats,
		&s.connStats,
		clientAddressValidated,
		s.conn.capabilities().ECN,
		s.receivedPacketHandler.IgnorePacketsBelow,
		s.perspective,
		congestion.Bandwidth(s.config.MaxPacingRate),
		s.qlogger,
		s.logger,
	)
	s.maxPayloadSizeEstimate.Store(uint32(estimateMaxPayloadSize(s.config.initialPacketSize())))
	statelessResetToken := statelessResetter.GetStatelessResetToken(srcConnID)
	params := &wire.TransportParameters{
		InitialMaxStreamDataBidiLocal:   protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataBidiRemote:  protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataUni:         protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxData:                  protocol.ByteCount(s.config.InitialConnectionReceiveWindow),
		MaxIdleTimeout:                  s.config.MaxIdleTimeout,
		MaxBidiStreamNum:                protocol.StreamNum(s.config.MaxIncomingStreams),
		MaxUniStreamNum:                 protocol.StreamNum(s.config.MaxIncomingUniStreams),
		MaxAckDelay:                     ackhandler.MaxAckDelay + protocol.TimerGranularity,
		AckDelayExponent:                protocol.AckDelayExponent,
		MaxUDPPayloadSize:               protocol.MaxPacketBufferSize,
		StatelessResetToken:             &statelessResetToken,
		OriginalDestinationConnectionID: origDestConnID,

		ActiveConnectionIDLimit:   protocol.MaxActiveConnectionIDs,
		InitialSourceConnectionID: srcConnID,
		RetrySourceConnectionID:   retrySrcConnID,
		EnableResetStreamAt:       conf.EnableStreamResetPartialDelivery,
	}
	if s.config.EnableDatagrams {
		params.MaxDatagramFrameSize = wire.MaxDatagramSize
	} else {
		params.MaxDatagramFrameSize = protocol.InvalidByteCount
	}
	if s.qlogger != nil {
		s.qlogTransportParameters(params, protocol.PerspectiveServer, false)
	}
	cs := handshake.NewCryptoSetupServer(
		clientDestConnID,
		conn.LocalAddr(),
		conn.RemoteAddr(),
		params,
		tlsConf,
		conf.Allow0RTT,
		s.rttStats,
		s.qlogger,
		logger,
		s.version,
	)
	s.cryptoStreamHandler = cs
	s.packer = newPacketPacker(srcConnID, s.connIDManager.Get, s.initialStream, s.handshakeStream, s.sentPacketHandler, s.retransmissionQueue, cs, s.framer, &s.receivedPacketHandler, s.datagramQueue, s.perspective, s.qlogger)
	s.unpacker = newPacketUnpacker(cs, s.srcConnIDLen)
	s.cryptoStreamManager = newCryptoStreamManager(s.initialStream, s.handshakeStream, s.oneRTTStream)
	return w
}

var newClientConnection = func(
	ctx context.Context,
	conn sendConn,
	runner connRunner,
	destConnID protocol.ConnectionID,
	srcConnID protocol.ConnectionID,
	connIDGenerator ConnectionIDGenerator,
	statelessResetter *statelessResetter,
	conf *Config,
	tlsConf *tls.Config,
	initialPacketNumber protocol.PacketNumber,
	enable0RTT bool,
	hasNegotiatedVersion bool,
	qlogTrace qlogwriter.Trace,
	logger utils.Logger,
	v protocol.Version,
) *wrappedConn {
	s := &Conn{
		conn:                conn,
		config:              conf,
		origDestConnID:      destConnID,
		handshakeDestConnID: destConnID,
		srcConnIDLen:        srcConnID.Len(),
		perspective:         protocol.PerspectiveClient,
		logID:               destConnID.String(),
		logger:              logger,
		qlogTrace:           qlogTrace,
		versionNegotiated:   hasNegotiatedVersion,
		version:             v,
	}
	w := &wrappedConn{pathReceiver: pathReceiver{Conn: s}}
	if qlogTrace != nil {
		s.qlogger = qlogTrace.AddProducer()
	}
	if s.qlogger != nil {
		var srcAddr, destAddr *net.UDPAddr
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			srcAddr = addr
		}
		if addr, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
			destAddr = addr
		}
		s.qlogger.RecordEvent(startedConnectionEvent(srcAddr, destAddr))
	}
	s.connIDManager = newConnIDManager(
		destConnID,
		func(token protocol.StatelessResetToken) { runner.AddResetToken(token, &w.pathReceiver) },
		runner.RemoveResetToken,
		s.queueControlFrame,
	)
	s.connIDGenerator = newConnIDGenerator(
		runner,
		srcConnID,
		nil,
		statelessResetter,
		&w.pathReceiver,
		s.queueControlFrame,
		connIDGenerator,
	)
	s.ctx, s.ctxCancel = context.WithCancelCause(ctx)
	s.preSetup(&w.pathReceiver)
	if len(tlsConf.ServerName) > 0 {
		s.tokenStoreKey = tlsConf.ServerName
	} else {
		s.tokenStoreKey = conn.RemoteAddr().String()
	}
	var token *ClientToken
	if s.config.TokenStore != nil {
		token = s.config.TokenStore.Pop(s.tokenStoreKey)
		if token != nil {
			s.rttStats.SetInitialRTT(token.rtt)
		}
	}
	s.sentPacketHandler = ackhandler.NewSentPacketHandlerWithPacingRate(
		initialPacketNumber,
		s.config.initialPacketSize(),
		s.rttStats,
		&s.connStats,
		false,
		s.conn.capabilities().ECN,
		s.receivedPacketHandler.IgnorePacketsBelow,
		s.perspective,
		congestion.Bandwidth(s.config.MaxPacingRate),
		s.qlogger,
		s.logger,
	)
	s.maxPayloadSizeEstimate.Store(uint32(estimateMaxPayloadSize(s.config.initialPacketSize())))
	oneRTTStream := newCryptoStream()
	params := &wire.TransportParameters{
		InitialMaxStreamDataBidiRemote: protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataBidiLocal:  protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataUni:        protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxData:                 protocol.ByteCount(s.config.InitialConnectionReceiveWindow),
		MaxIdleTimeout:                 s.config.MaxIdleTimeout,
		MaxBidiStreamNum:               protocol.StreamNum(s.config.MaxIncomingStreams),
		MaxUniStreamNum:                protocol.StreamNum(s.config.MaxIncomingUniStreams),
		MaxAckDelay:                    ackhandler.MaxAckDelay + protocol.TimerGranularity,
		MaxUDPPayloadSize:              protocol.MaxPacketBufferSize,
		AckDelayExponent:               protocol.AckDelayExponent,

		ActiveConnectionIDLimit:   protocol.MaxActiveConnectionIDs,
		InitialSourceConnectionID: srcConnID,
		EnableResetStreamAt:       conf.EnableStreamResetPartialDelivery,
	}
	if s.config.EnableDatagrams {
		params.MaxDatagramFrameSize = wire.MaxDatagramSize
	} else {
		params.MaxDatagramFrameSize = protocol.InvalidByteCount
	}
	if s.qlogger != nil {
		s.qlogTransportParameters(params, protocol.PerspectiveClient, false)
	}
	cs := handshake.NewCryptoSetupClient(
		destConnID,
		params,
		tlsConf,
		enable0RTT,
		s.rttStats,
		s.qlogger,
		logger,
		s.version,
	)
	s.cryptoStreamHandler = cs
	s.cryptoStreamManager = newCryptoStreamManager(s.initialStream, s.handshakeStream, oneRTTStream)
	s.unpacker = newPacketUnpacker(cs, s.srcConnIDLen)
	s.packer = newPacketPacker(srcConnID, s.connIDManager.Get, s.initialStream, s.handshakeStream, s.sentPacketHandler, s.retransmissionQueue, cs, s.framer, &s.receivedPacketHandler, s.datagramQueue, s.perspective, s.qlogger)
	if token != nil {
		s.packer.SetToken(token.data)
	}
	return w
}

// r is the pathReceiver for the Transport that the connection was dialed or accepted on.
func (c *Conn) preSetup(r *pathReceiver) {
	c.largestRcvdAppData = protocol.InvalidPacketNumber
	c.initialStream = newInitialCryptoStream(c.perspective == protocol.PerspectiveClient)
	c.handshakeStream = newCryptoStream()
	c.sendQueue = newSendQueue(c.conn)
	c.retransmissionQueue = newRetransmissionQueue()
	c.frameParser = *wire.NewFrameParser(
		c.config.EnableDatagrams,
		c.config.EnableStreamResetPartialDelivery,
		false,
	)
	c.rttStats = utils.NewRTTStats()
	c.connFlowController = newConnectionFlowController(
		protocol.ByteCount(c.config.InitialConnectionReceiveWindow),
		protocol.ByteCount(c.config.MaxConnectionReceiveWindow),
		func(size protocol.ByteCount) bool {
			if c.config.AllowConnectionWindowIncrease == nil {
				return true
			}
			return c.config.AllowConnectionWindowIncrease(c, uint64(size))
		},
		c.rttStats,
		c.logger,
	)
	c.earlyConnReadyChan = make(chan struct{})
	c.streamsMap = newStreamsMap(
		c.ctx,
		c,
		c.queueControlFrame,
		c.newFlowController,
		uint64(c.config.MaxIncomingStreams),
		uint64(c.config.MaxIncomingUniStreams),
		c.config.RequireStreamCreditRelease,
		c.perspective,
	)
	c.framer = newFramer(c.connFlowController)
	c.receivedPackets.Init(r)
	c.notifyReceivedPacket = make(chan struct{}, 1)
	c.closeChan = make(chan struct{}, 1)
	c.sendingScheduled = make(chan struct{}, 1)
	c.handshakeCompleteChan = make(chan struct{})

	now := monotime.Now()
	c.lastPacketReceivedTime = now
	c.creationTime = now

	c.receivedPacketHandler = *ackhandler.NewReceivedPacketHandler(c.logger)

	c.datagramQueue = newDatagramQueue(c.scheduleSending, c.logger, c.qlogger)
	c.connState.Version = c.version
}

func (c *Conn) run() (err error) {
	defer func() { c.ctxCancel(err) }()

	// drain queued packets that will never be processed
	defer c.receivedPackets.Clear()

	c.timer = time.NewTimer(monotime.Until(c.idleTimeoutStartTime().Add(c.config.HandshakeIdleTimeout)))

	if err := c.cryptoStreamHandler.StartHandshake(c.ctx); err != nil {
		return err
	}
	if err := c.handleHandshakeEvents(monotime.Now()); err != nil {
		return err
	}
	go func() {
		if err := c.sendQueue.Run(); err != nil {
			c.destroyImpl(err)
		}
	}()

	if c.perspective == protocol.PerspectiveClient {
		c.scheduleSending()
	}

	var sendQueueAvailable <-chan struct{}

runLoop:
	for {
		if c.framer.QueuedTooManyControlFrames() {
			c.setCloseError(&closeError{err: &qerr.TransportError{ErrorCode: InternalError}})
			break runLoop
		}

		select {
		case <-c.closeChan:
			break runLoop
		default:
		}

		if c.pacingDeadline != deadlineSendImmediately {
			c.maybeResetTimer()
		}

		if len(c.undecryptablePacketsToProcess) > 0 {
			var processedUndecryptablePacket bool
			queue := c.undecryptablePacketsToProcess
			c.undecryptablePacketsToProcess = nil
			for _, p := range queue {
				// undecryptable packets are only queued during the handshake, i.e. on the active path
				processed, err := c.handleOnePacket(p.receivedPacket, p.checksum, activePathID)
				if err != nil {
					c.setCloseError(&closeError{err: err})
					break runLoop
				}
				if processed {
					processedUndecryptablePacket = true
				}
			}
			if processedUndecryptablePacket {
				continue
			}
		}

		processed, err := c.handlePackets()
		if err != nil {
			c.setCloseError(&closeError{err: err})
			break runLoop
		}

		shouldProceedImmediately := sendQueueAvailable == nil && (processed || c.pacingDeadline.Equal(deadlineSendImmediately))
		if !shouldProceedImmediately {
			select {
			case <-c.closeChan:
				break runLoop
			case <-c.timer.C:
			case <-c.sendingScheduled:
			case <-sendQueueAvailable:
			case <-c.notifyReceivedPacket:
				wasProcessed, err := c.handlePackets()
				if err != nil {
					c.setCloseError(&closeError{err: err})
					break runLoop
				}

				if !wasProcessed {
					continue
				}
			}
		}

		now := monotime.Now()
		if timeout := c.sentPacketHandler.GetLossDetectionTimeout(); !timeout.IsZero() && !timeout.After(now) {
			if err := c.sentPacketHandler.OnLossDetectionTimeout(now); err != nil {
				c.setCloseError(&closeError{err: err})
				break runLoop
			}
		}

		if keepAliveTime := c.nextKeepAliveTime(); !keepAliveTime.IsZero() && !now.Before(keepAliveTime) {

			c.logger.Debugf("Sending a keep-alive PING to keep the connection alive.")
			c.framer.QueueControlFrame(&wire.PingFrame{})
			c.keepAlivePingSent = true
		} else if !c.handshakeComplete && now.Sub(c.creationTime) >= c.config.handshakeTimeout() {
			c.destroyImpl(qerr.ErrHandshakeTimeout)
			break runLoop
		} else {
			idleTimeoutStartTime := c.idleTimeoutStartTime()
			if (!c.handshakeComplete && now.Sub(idleTimeoutStartTime) >= c.config.HandshakeIdleTimeout) ||
				(c.handshakeComplete && !now.Before(c.nextIdleTimeoutTime())) {
				c.destroyImpl(qerr.ErrIdleTimeout)
				break runLoop
			}
		}

		c.connIDGenerator.RemoveRetiredConnIDs(now)

		if c.perspective == protocol.PerspectiveClient {
			pm := c.pathManagerOutgoing.Load()
			if pm != nil {
				id, tr, ok := pm.ShouldSwitchPath()
				if ok {
					c.connIDManager.SwitchToPath(id)
					c.switchToNewPath(tr, now)
				}
			}
		}

		if c.sendQueue.WouldBlock() {

			sendQueueAvailable = c.sendQueue.Available()

			c.pacingDeadline = 0
			c.blocked = blockModeHardBlocked
			continue
		}

		if c.closeErr.Load() != nil {
			break runLoop
		}

		c.blocked = blockModeNone
		if err := c.triggerSending(now); err != nil {
			c.setCloseError(&closeError{err: err})
			break runLoop
		}
		if c.sendQueue.WouldBlock() {

			sendQueueAvailable = c.sendQueue.Available()

			c.pacingDeadline = 0
			c.blocked = blockModeHardBlocked
		} else {
			sendQueueAvailable = nil
		}
	}

	closeErr := c.closeErr.Load()
	c.cryptoStreamHandler.Close()
	c.sendQueue.Close()
	c.handleCloseError(closeErr)
	if c.qlogger != nil {
		if _, ok := errors.AsType[*errCloseForRecreating](closeErr.err); !ok {
			c.qlogger.Close()
		}
	}
	c.logger.Infof("Connection %s closed.", c.logID)
	c.timer.Stop()
	return closeErr.err
}

func (c *Conn) earlyConnReady() <-chan struct{} {
	return c.earlyConnReadyChan
}

func (c *Conn) Context() context.Context {
	return c.ctx
}

func (c *Conn) supportsDatagrams() bool {
	return c.peerParams.MaxDatagramFrameSize > 0
}

func (c *Conn) ConnectionState() ConnectionState {
	c.connStateMutex.Lock()
	defer c.connStateMutex.Unlock()

	cs := c.cryptoStreamHandler.ConnectionState()
	c.connState.TLS = cs.ConnectionState
	c.connState.Used0RTT = cs.Used0RTT
	if c.peerParams != nil {
		c.connState.SupportsDatagrams.Remote = c.supportsDatagrams()
		c.connState.SupportsStreamResetPartialDelivery.Remote = c.peerParams.EnableResetStreamAt
	}
	c.connState.SupportsDatagrams.Local = c.config.EnableDatagrams
	c.connState.SupportsStreamResetPartialDelivery.Local = c.config.EnableStreamResetPartialDelivery
	c.connState.RequireStreamCreditRelease = c.config.RequireStreamCreditRelease
	c.connState.GSO = c.conn.capabilities().GSO
	return c.connState
}

type ConnectionStats struct {
	MinRTT time.Duration

	LatestRTT time.Duration

	SmoothedRTT time.Duration

	MeanDeviation time.Duration

	CongestionWindow uint64

	BytesSent uint64

	PacketsSent uint64

	BytesReceived uint64

	PacketsReceived uint64

	BytesLost uint64

	PacketsLost uint64
}

func (c *Conn) ConnectionStats() ConnectionStats {
	return ConnectionStats{
		MinRTT:        c.rttStats.MinRTT(),
		LatestRTT:     c.rttStats.LatestRTT(),
		SmoothedRTT:   c.rttStats.SmoothedRTT(),
		MeanDeviation: c.rttStats.MeanDeviation(),

		CongestionWindow: c.connStats.CongestionWindow.Load(),

		BytesSent:       c.connStats.BytesSent.Load(),
		PacketsSent:     c.connStats.PacketsSent.Load(),
		BytesReceived:   c.connStats.BytesReceived.Load(),
		PacketsReceived: c.connStats.PacketsReceived.Load(),
		BytesLost:       c.connStats.BytesLost.Load(),
		PacketsLost:     c.connStats.PacketsLost.Load(),
	}
}

func (c *Conn) nextIdleTimeoutTime() monotime.Time {
	idleTimeout := max(c.idleTimeout, c.rttStats.PTO(true)*3)
	return c.idleTimeoutStartTime().Add(idleTimeout)
}

func (c *Conn) nextKeepAliveTime() monotime.Time {
	if c.config.KeepAlivePeriod == 0 || c.keepAlivePingSent {
		return 0
	}
	keepAliveInterval := max(c.keepAliveInterval, c.rttStats.PTO(true)*3/2)
	return c.lastPacketReceivedTime.Add(keepAliveInterval)
}

func (c *Conn) maybeResetTimer() {
	var deadline monotime.Time
	if !c.handshakeComplete {
		deadline = c.creationTime.Add(c.config.handshakeTimeout())
		if t := c.idleTimeoutStartTime().Add(c.config.HandshakeIdleTimeout); t.Before(deadline) {
			deadline = t
		}
	} else {
		if c.blocked != blockModeNone {
			deadline = c.nextIdleTimeoutTime()
		} else {
			if keepAliveTime := c.nextKeepAliveTime(); !keepAliveTime.IsZero() {
				deadline = keepAliveTime
			} else {
				deadline = c.nextIdleTimeoutTime()
			}
		}
	}

	if c.blocked == blockModeHardBlocked {
		c.timer.Reset(monotime.Until(deadline))
		return
	}

	if t := c.receivedPacketHandler.GetAlarmTimeout(); !t.IsZero() && t.Before(deadline) {
		deadline = t
	}
	if t := c.sentPacketHandler.GetLossDetectionTimeout(); !t.IsZero() && t.Before(deadline) {
		deadline = t
	}
	if c.blocked == blockModeCongestionLimited {
		c.timer.Reset(monotime.Until(deadline))
		return
	}

	if !c.pacingDeadline.IsZero() && c.pacingDeadline.Before(deadline) {
		deadline = c.pacingDeadline
	}
	c.timer.Reset(monotime.Until(deadline))
}

func (c *Conn) idleTimeoutStartTime() monotime.Time {
	startTime := c.lastPacketReceivedTime
	if t := c.firstAckElicitingPacketAfterIdleSentTime; !t.IsZero() && t.After(startTime) {
		startTime = t
	}
	return startTime
}

func (c *Conn) switchToNewPath(tr *Transport, now monotime.Time) {
	// The connection is registered with the Transport, since it was probed before switching to it.
	if h, ok := c.connIDGenerator.Handler((*packetHandlerMap)(tr)); ok {
		if prev := c.receivedPackets.SwapActive(h); prev != h && c.qlogger != nil {
			// from now on, the old path needs to be logged with its own TupleID
			c.qlogger.RecordEvent(tupleAssignedEvent(strconv.FormatInt(int64(prev.id), 10), c.conn.LocalAddr(), c.conn.RemoteAddr()))
			c.qlogger.RecordEvent(tupleAssignedEvent("", tr.Conn.LocalAddr(), c.conn.RemoteAddr()))
		}
	}

	initialPacketSize := protocol.ByteCount(cmp.Or(c.config.InitialPacketSize, protocol.MinInitialPacketSize))
	c.sentPacketHandler.MigratedPath(now, initialPacketSize)
	c.maxPayloadSizeEstimate.Store(uint32(estimateMaxPayloadSize(initialPacketSize)))
	c.mtuDiscoverer.Reset(initialPacketSize, c.maxMTU())
	c.conn = newSendConn(tr.conn, c.conn.RemoteAddr(), packetInfo{}, utils.DefaultLogger)
	if !c.config.DisablePathMTUDiscovery && c.conn.capabilities().DF {
		c.mtuDiscoverer.Start(now)
	}
	c.sendQueue.Close()
	c.sendQueue = newSendQueue(c.conn)
	go func() {
		if err := c.sendQueue.Run(); err != nil {
			c.destroyImpl(err)
		}
	}()
}

func (c *Conn) handleHandshakeComplete(now monotime.Time) error {
	defer close(c.handshakeCompleteChan)

	c.undecryptablePackets = nil

	c.connIDManager.SetHandshakeComplete()
	c.connIDGenerator.SetHandshakeComplete(now.Add(3 * c.rttStats.PTO(false)))

	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.ALPNInformation{
			ChosenALPN: c.cryptoStreamHandler.ConnectionState().NegotiatedProtocol,
		})
	}

	if c.perspective == protocol.PerspectiveClient {
		c.applyTransportParameters()
		return nil
	}

	if err := c.handleHandshakeConfirmed(now); err != nil {
		return err
	}

	ticket, err := c.cryptoStreamHandler.GetSessionTicket()
	if err != nil {
		return err
	}
	if ticket != nil {
		c.oneRTTStream.Write(ticket)
		if cf := c.oneRTTStream.PopCryptoFrame(protocol.MaxByteCount); cf != nil {
			c.queueControlFrame(cf)
		}
	}
	token, err := c.tokenGenerator.NewToken(c.conn.RemoteAddr(), c.rttStats.SmoothedRTT())
	if err != nil {
		return err
	}
	c.queueControlFrame(&wire.NewTokenFrame{Token: token})
	c.queueControlFrame(&wire.HandshakeDoneFrame{})
	return nil
}

func (c *Conn) handleHandshakeConfirmed(now monotime.Time) error {
	c.dropEncryptionLevel(protocol.EncryptionInitial, now)
	c.dropEncryptionLevel(protocol.EncryptionHandshake, now)

	c.handshakeConfirmed = true
	c.cryptoStreamHandler.SetHandshakeConfirmed()

	if !c.config.DisablePathMTUDiscovery && c.conn.capabilities().DF {
		c.mtuDiscoverer.Start(now)
	}
	return nil
}

const maxPacketsToProcess = 32

func (c *Conn) handlePackets() (wasProcessed bool, _ error) {
	// Process packets from the receivedPackets queue.
	// Limit the number of packets to process to maxPacketsToProcess,
	// so we eventually get a chance to send out an ACK when receiving a lot of packets.
	for range maxPacketsToProcess {
		p, path, ok := c.receivedPackets.Pop()
		if !ok {
			return wasProcessed, nil
		}

		var datagramPayloadChecksum qlog.DatagramPayloadChecksum
		if c.qlogger != nil && wire.IsLongHeaderPacket(p.data[0]) {
			datagramPayloadChecksum = qlog.CalculateDatagramPayloadChecksum(p.data)
		}
		processed, err := c.handleOnePacket(p, datagramPayloadChecksum, path)
		if err != nil {
			return false, err
		}
		if processed {
			wasProcessed = true
		}
		// Prioritize sending of new CRYPTO data.
		// This is especially relevant when processing 0-RTT packets.
		if !c.handshakeComplete && (c.initialStream.HasData() || c.handshakeStream.HasData()) {
			break
		}
	}

	if !c.receivedPackets.Empty() {
		select {
		case c.notifyReceivedPacket <- struct{}{}:
		default:
		}
	}
	return wasProcessed, nil
}

func (c *Conn) handleOnePacket(
	rp receivedPacket,
	datagramPayloadChecksum qlog.DatagramPayloadChecksum, // only for logging
	path pathID, // only for logging
) (wasProcessed bool, _ error) {
	c.sentPacketHandler.ReceivedBytes(rp.Size(), rp.rcvTime)

	if wire.IsVersionNegotiationPacket(rp.data) {
		return false, c.handleVersionNegotiationPacket(rp)
	}

	var counter uint8
	var lastConnID protocol.ConnectionID
	data := rp.data
	p := rp
	for len(data) > 0 {
		if counter > 0 {
			p = *p.Clone()
			p.data = data

			destConnID, err := wire.ParseConnectionID(p.data, c.srcConnIDLen)
			if err != nil {
				if c.qlogger != nil {
					c.qlogger.RecordEvent(qlog.PacketDropped{
						Raw:                     qlog.RawInfo{Length: len(data), PayloadLength: qlog.OmitLength},
						DatagramPayloadChecksum: datagramPayloadChecksum,
						Trigger:                 qlog.PacketDropHeaderParseError,
					})
				}
				c.logger.Debugf("error parsing packet, couldn't parse connection ID: %s", err)
				break
			}
			if destConnID != lastConnID {
				if c.qlogger != nil {
					c.qlogger.RecordEvent(qlog.PacketDropped{
						Header:                  qlog.PacketHeader{DestConnectionID: destConnID},
						Raw:                     qlog.RawInfo{Length: len(data), PayloadLength: qlog.OmitLength},
						DatagramPayloadChecksum: datagramPayloadChecksum,
						Trigger:                 qlog.PacketDropUnknownConnectionID,
					})
				}
				c.logger.Debugf("coalesced packet has different destination connection ID: %s, expected %s", destConnID, lastConnID)
				break
			}
		}

		if wire.IsLongHeaderPacket(p.data[0]) {
			hdr, packetData, rest, err := wire.ParsePacket(p.data)
			if err != nil {
				if c.qlogger != nil {
					if err == wire.ErrUnsupportedVersion {
						c.qlogger.RecordEvent(qlog.PacketDropped{
							Header:                  qlog.PacketHeader{Version: hdr.Version},
							Raw:                     qlog.RawInfo{Length: len(data), PayloadLength: qlog.OmitLength},
							DatagramPayloadChecksum: datagramPayloadChecksum,
							Trigger:                 qlog.PacketDropUnsupportedVersion,
						})
					} else {
						c.qlogger.RecordEvent(qlog.PacketDropped{
							Raw:                     qlog.RawInfo{Length: len(data), PayloadLength: qlog.OmitLength},
							DatagramPayloadChecksum: datagramPayloadChecksum,
							Trigger:                 qlog.PacketDropHeaderParseError,
						})
					}
				}
				c.logger.Debugf("error parsing packet: %s", err)
				break
			}
			lastConnID = hdr.DestConnectionID

			if hdr.Version != c.version {
				if c.qlogger != nil {
					c.qlogger.RecordEvent(qlog.PacketDropped{
						Raw:                     qlog.RawInfo{Length: len(data), PayloadLength: qlog.OmitLength},
						DatagramPayloadChecksum: datagramPayloadChecksum,
						Trigger:                 qlog.PacketDropUnexpectedVersion,
					})
				}
				c.logger.Debugf("Dropping packet with version %x. Expected %x.", hdr.Version, c.version)
				break
			}

			if counter > 0 {
				p.buffer.Split()
			}
			counter++

			if c.logger.Debug() && (counter > 1 || len(rest) > 0) {
				c.logger.Debugf("Parsed a coalesced packet. Part %d: %d bytes. Remaining: %d bytes.", counter, len(packetData), len(rest))
			}

			p.data = packetData

			processed, err := c.handleLongHeaderPacket(p, hdr, datagramPayloadChecksum)
			if err != nil {
				return false, err
			}
			if processed {
				wasProcessed = true
			}
			data = rest
		} else {
			if counter > 0 {
				p.buffer.Split()
			}
			processed, err := c.handleShortHeaderPacket(p, counter > 0, datagramPayloadChecksum, path)
			if err != nil {
				return false, err
			}
			if processed {
				wasProcessed = true
			}
			break
		}
	}

	p.buffer.MaybeRelease()
	c.blocked = blockModeNone
	return wasProcessed, nil
}

func (c *Conn) handleShortHeaderPacket(
	p receivedPacket,
	isCoalesced bool,
	datagramPayloadChecksum qlog.DatagramPayloadChecksum, // only for logging
	path pathID, // only for logging
) (wasProcessed bool, _ error) {
	var wasQueued bool

	defer func() {
		if !wasQueued {
			p.buffer.Decrement()
		}
	}()

	destConnID, err := wire.ParseConnectionID(p.data, c.srcConnIDLen)
	if err != nil {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketType1RTT,
					PacketNumber: protocol.InvalidPacketNumber,
				},
				Raw:                     qlog.RawInfo{Length: len(p.data), PayloadLength: qlog.OmitLength},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropHeaderParseError,
			})
		}
		return false, nil
	}
	pn, pnLen, keyPhase, data, err := c.unpacker.UnpackShortHeader(p.rcvTime, p.data)
	if err != nil {

		if !isCoalesced && len(p.data) >= protocol.MinReceivedStatelessResetSize && p.data[0]&0b11000000 == 0b01000000 {
			token := protocol.StatelessResetToken(p.data[len(p.data)-16:])
			if c.connIDManager.IsActiveStatelessResetToken(token) {
				return false, &StatelessResetError{}
			}
		}
		wasQueued, err = c.handleUnpackError(err, p, qlog.PacketType1RTT, datagramPayloadChecksum)
		return false, err
	}
	c.largestRcvdAppData = max(c.largestRcvdAppData, pn)

	if c.logger.Debug() {
		c.logger.Debugf("<- Reading packet %d (%d bytes) for connection %s, 1-RTT", pn, p.Size(), destConnID)
		wire.LogShortHeader(c.logger, destConnID, pn, pnLen, keyPhase)
	}

	if c.receivedPacketHandler.IsPotentiallyDuplicate(pn, protocol.PacketNumberSpaceAppData) {
		c.logger.Debugf("Dropping (potentially) duplicate packet.")
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketType1RTT,
					PacketNumber: pn,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size()), PayloadLength: qlog.OmitLength},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropDuplicate,
			})
		}
		return false, nil
	}

	// Only the client can migrate between paths, so only the server receives packets from different addresses.
	// The path is created before handling the frames, so that the packet can be logged with the path's tuple.
	checkPath := c.perspective == protocol.PerspectiveServer && !addrsEqual(p.remoteAddr, c.RemoteAddr())
	if checkPath {
		if c.pathManager == nil {
			c.pathManager = newPathManager(
				c.connIDManager.GetConnIDForPath,
				c.connIDManager.RetireConnIDForPath,
				c.logger,
			)
		}
		if id, isNew, ok := c.pathManager.GetOrCreatePath(p.remoteAddr, p.rcvTime); ok {
			path = id
			if isNew && c.qlogger != nil {
				c.qlogger.RecordEvent(tupleAssignedEvent(strconv.FormatInt(int64(id), 10), c.conn.LocalAddr(), p.remoteAddr))
			}
		}
	}

	var log func([]qlog.Frame)
	if c.qlogger != nil {
		var tuple string
		if path != activePathID {
			tuple = strconv.FormatInt(int64(path), 10)
		}
		log = func(frames []qlog.Frame) {
			c.qlogger.RecordEvent(qlog.PacketReceived{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketType1RTT,
					DestConnectionID: destConnID,
					PacketNumber:     pn,
					KeyPhaseBit:      keyPhase,
				},
				Raw: qlog.RawInfo{
					Length:        int(p.Size()),
					PayloadLength: int(p.Size() - wire.ShortHeaderLen(destConnID, pnLen)),
				},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Frames:                  frames,
				ECN:                     toQlogECN(p.ecn),
				Tuple:                   tuple,
			})
		}
	}
	isNonProbing, pathChallenge, err := c.handleUnpackedShortHeaderPacket(destConnID, pn, data, p.ecn, p.rcvTime, log)
	if err != nil {
		return false, err
	}
	if pathChallenge != nil && c.perspective == protocol.PerspectiveClient {
		if err := c.handlePathChallengeFrame(pathChallenge, path, p.rcvTime); err != nil {
			return true, err
		}
	}

	if !checkPath {
		return true, nil
	}
	destConnID, frames, shouldSwitchPath := c.pathManager.HandlePacket(p.remoteAddr, p.rcvTime, pathChallenge, isNonProbing)
	if len(frames) > 0 {
		probe, buf, err := c.packer.PackPathProbePacket(destConnID, frames, c.version)
		if err != nil {
			return true, err
		}
		c.logger.Debugf("sending path probe packet to %s", p.remoteAddr)
		c.logShortHeaderPacketWithDatagramPayloadChecksum(probe, protocol.ECNNon, buf.Len(), false, datagramPayloadChecksum, strconv.FormatInt(int64(path), 10))
		c.registerPackedShortHeaderPacket(probe, protocol.ECNNon, p.rcvTime)
		c.sendQueue.SendProbe(buf, p.remoteAddr, p.info)
	}

	if !shouldSwitchPath || pn != c.largestRcvdAppData {
		return true, nil
	}
	c.pathManager.SwitchToPath(p.remoteAddr)
	c.connIDManager.SwitchToPath(path)
	initialPacketSize := protocol.ByteCount(cmp.Or(c.config.InitialPacketSize, protocol.MinInitialPacketSize))
	c.sentPacketHandler.MigratedPath(p.rcvTime, initialPacketSize)
	c.maxPayloadSizeEstimate.Store(uint32(estimateMaxPayloadSize(initialPacketSize)))
	c.mtuDiscoverer.Reset(initialPacketSize, c.maxMTU())
	if !c.config.DisablePathMTUDiscovery && c.conn.capabilities().DF {
		c.mtuDiscoverer.Start(p.rcvTime)
	}
	c.conn.ChangeRemoteAddr(p.remoteAddr, p.info)
	if c.qlogger != nil {
		// the TupleID "" refers to the active path
		c.qlogger.RecordEvent(tupleAssignedEvent("", c.conn.LocalAddr(), p.remoteAddr))
	}
	return true, nil
}

func (c *Conn) handleLongHeaderPacket(p receivedPacket, hdr *wire.Header, datagramPayloadChecksum qlog.DatagramPayloadChecksum) (wasProcessed bool, _ error) {
	var wasQueued bool

	defer func() {
		if !wasQueued {
			p.buffer.Decrement()
		}
	}()

	if hdr.Type == protocol.PacketTypeRetry {
		return c.handleRetryPacket(hdr, p.data, p.rcvTime), nil
	}

	if c.receivedFirstPacket && hdr.Type == protocol.PacketTypeInitial && hdr.SrcConnectionID != c.handshakeDestConnID {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketTypeInitial,
					PacketNumber: protocol.InvalidPacketNumber,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size()), PayloadLength: qlog.OmitLength},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropUnknownConnectionID,
			})
		}
		c.logger.Debugf("Dropping Initial packet (%d bytes) with unexpected source connection ID: %s (expected %s)", p.Size(), hdr.SrcConnectionID, c.handshakeDestConnID)
		return false, nil
	}

	if c.perspective == protocol.PerspectiveClient && hdr.Type == protocol.PacketType0RTT {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketType0RTT,
					PacketNumber: protocol.InvalidPacketNumber,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size()), PayloadLength: qlog.OmitLength},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropUnexpectedPacket,
			})
		}
		return false, nil
	}
	// The client switches to the server's connection ID before it can send Handshake packets.
	if hdr.Type == protocol.PacketTypeHandshake && c.connIDGenerator.IsInitialClientDestConnID(hdr.DestConnectionID) {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeHandshake,
					DestConnectionID: hdr.DestConnectionID,
					SrcConnectionID:  hdr.SrcConnectionID,
					PacketNumber:     protocol.InvalidPacketNumber,
					Version:          hdr.Version,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size()), PayloadLength: qlog.OmitLength},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropUnknownConnectionID,
			})
		}
		c.logger.Debugf("Dropping Handshake packet (%d bytes) sent to the client's Initial destination connection ID: %s", p.Size(), hdr.DestConnectionID)
		return false, nil
	}

	packet, err := c.unpacker.UnpackLongHeader(hdr, p.data)
	if err != nil {
		wasQueued, err = c.handleUnpackError(err, p, toQlogPacketType(hdr.Type), datagramPayloadChecksum)
		return false, err
	}

	if c.logger.Debug() {
		c.logger.Debugf("<- Reading packet %d (%d bytes) for connection %s, %s", packet.hdr.PacketNumber, p.Size(), hdr.DestConnectionID, packet.encryptionLevel)
		packet.hdr.Log(c.logger)
	}

	if pn := packet.hdr.PacketNumber; c.receivedPacketHandler.IsPotentiallyDuplicate(pn, packet.encryptionLevel.PacketNumberSpace()) {
		c.logger.Debugf("Dropping (potentially) duplicate packet.")
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       toQlogPacketType(packet.hdr.Type),
					DestConnectionID: hdr.DestConnectionID,
					SrcConnectionID:  hdr.SrcConnectionID,
					PacketNumber:     pn,
					Version:          packet.hdr.Version,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size()), PayloadLength: int(packet.hdr.Length)},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropDuplicate,
			})
		}
		return false, nil
	}

	if err := c.handleUnpackedLongHeaderPacket(packet, p.ecn, p.rcvTime, datagramPayloadChecksum, p.Size()); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Conn) handleUnpackError(err error, p receivedPacket, pt qlog.PacketType, datagramPayloadChecksum qlog.DatagramPayloadChecksum) (wasQueued bool, _ error) {
	switch err {
	case handshake.ErrKeysDropped:
		if c.qlogger != nil {
			connID, _ := wire.ParseConnectionID(p.data, c.srcConnIDLen)
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       pt,
					DestConnectionID: connID,
					PacketNumber:     protocol.InvalidPacketNumber,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size()), PayloadLength: qlog.OmitLength},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropKeyUnavailable,
			})
		}
		c.logger.Debugf("Dropping %s packet (%d bytes) because we already dropped the keys.", pt, p.Size())
		return false, nil
	case handshake.ErrKeysNotYetAvailable:

		c.tryQueueingUndecryptablePacket(p, pt, datagramPayloadChecksum)
		return true, nil
	case wire.ErrInvalidReservedBits:
		return false, &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: err.Error(),
		}
	case handshake.ErrDecryptionFailed:

		if c.qlogger != nil {
			connID, _ := wire.ParseConnectionID(p.data, c.srcConnIDLen)
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       pt,
					DestConnectionID: connID,
					PacketNumber:     protocol.InvalidPacketNumber,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size()), PayloadLength: qlog.OmitLength},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropPayloadDecryptError,
			})
		}
		c.logger.Debugf("Dropping %s packet (%d bytes) that could not be unpacked. Error: %s", pt, p.Size(), err)
		return false, nil
	default:
		if _, ok := errors.AsType[*headerParseError](err); ok {

			if c.qlogger != nil {
				connID, _ := wire.ParseConnectionID(p.data, c.srcConnIDLen)
				c.qlogger.RecordEvent(qlog.PacketDropped{
					Header: qlog.PacketHeader{
						PacketType:       pt,
						DestConnectionID: connID,
						PacketNumber:     protocol.InvalidPacketNumber,
					},
					Raw:                     qlog.RawInfo{Length: int(p.Size()), PayloadLength: qlog.OmitLength},
					DatagramPayloadChecksum: datagramPayloadChecksum,
					Trigger:                 qlog.PacketDropHeaderParseError,
				})
			}
			c.logger.Debugf("Dropping %s packet (%d bytes) for which we couldn't unpack the header. Error: %s", pt, p.Size(), err)
			return false, nil
		}

		return false, err
	}
}

func (c *Conn) handleRetryPacket(hdr *wire.Header, data []byte, rcvTime monotime.Time) bool {
	if c.perspective == protocol.PerspectiveServer {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  hdr.SrcConnectionID,
					DestConnectionID: hdr.DestConnectionID,
					Version:          hdr.Version,
				},
				Raw:     qlog.RawInfo{Length: len(data), PayloadLength: qlog.OmitLength},
				Trigger: qlog.PacketDropUnexpectedPacket,
			})
		}
		c.logger.Debugf("Ignoring Retry.")
		return false
	}
	if c.receivedFirstPacket {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  hdr.SrcConnectionID,
					DestConnectionID: hdr.DestConnectionID,
					Version:          hdr.Version,
				},
				Raw:     qlog.RawInfo{Length: len(data), PayloadLength: qlog.OmitLength},
				Trigger: qlog.PacketDropUnexpectedPacket,
			})
		}
		c.logger.Debugf("Ignoring Retry, since we already received a packet.")
		return false
	}
	destConnID := c.connIDManager.Get()
	if hdr.SrcConnectionID == destConnID {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  hdr.SrcConnectionID,
					DestConnectionID: hdr.DestConnectionID,
					Version:          hdr.Version,
				},
				Raw:     qlog.RawInfo{Length: len(data), PayloadLength: qlog.OmitLength},
				Trigger: qlog.PacketDropUnexpectedPacket,
			})
		}
		c.logger.Debugf("Ignoring Retry, since the server didn't change the Source Connection ID.")
		return false
	}

	if c.receivedRetry {
		c.logger.Debugf("Ignoring Retry, since a Retry was already received.")
		return false
	}

	tag := handshake.GetRetryIntegrityTag(data[:len(data)-16], destConnID, hdr.Version)
	if !bytes.Equal(data[len(data)-16:], tag[:]) {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  hdr.SrcConnectionID,
					DestConnectionID: hdr.DestConnectionID,
					Version:          hdr.Version,
				},
				Raw:     qlog.RawInfo{Length: len(data), PayloadLength: qlog.OmitLength},
				Trigger: qlog.PacketDropPayloadDecryptError,
			})
		}
		c.logger.Debugf("Ignoring spoofed Retry. Integrity Tag doesn't match.")
		return false
	}

	newDestConnID := hdr.SrcConnectionID
	c.receivedRetry = true
	c.sentPacketHandler.ResetForRetry(rcvTime)
	c.handshakeDestConnID = newDestConnID
	c.retrySrcConnID = &newDestConnID
	c.cryptoStreamHandler.ChangeConnectionID(newDestConnID)
	c.packer.SetToken(hdr.Token)
	c.connIDManager.ChangeInitialConnID(newDestConnID)

	if c.logger.Debug() {
		c.logger.Debugf("<- Received Retry:")
		(&wire.ExtendedHeader{Header: *hdr}).Log(c.logger)
		c.logger.Debugf("Switching destination connection ID to: %s", hdr.SrcConnectionID)
	}
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.PacketReceived{
			Header: qlog.PacketHeader{
				PacketType:       qlog.PacketTypeRetry,
				DestConnectionID: destConnID,
				SrcConnectionID:  newDestConnID,
				Version:          hdr.Version,
				Token:            &qlog.Token{Raw: hdr.Token},
			},
			Raw: qlog.RawInfo{Length: len(data), PayloadLength: qlog.OmitLength},
		})
	}

	c.scheduleSending()
	return true
}

func (c *Conn) handleVersionNegotiationPacket(p receivedPacket) error {
	if c.perspective == protocol.PerspectiveServer || // servers never receive version negotiation packets
		c.receivedFirstPacket || c.receivedRetry || c.versionNegotiated { // ignore version negotiation packets received after any other packet
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header:  qlog.PacketHeader{PacketType: qlog.PacketTypeVersionNegotiation},
				Raw:     qlog.RawInfo{Length: int(p.Size()), PayloadLength: qlog.OmitLength},
				Trigger: qlog.PacketDropUnexpectedPacket,
			})
		}
		return nil
	}

	dest, src, supportedVersions, err := wire.ParseVersionNegotiationPacket(p.data)
	if err != nil {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header:  qlog.PacketHeader{PacketType: qlog.PacketTypeVersionNegotiation},
				Raw:     qlog.RawInfo{Length: int(p.Size()), PayloadLength: qlog.OmitLength},
				Trigger: qlog.PacketDropHeaderParseError,
			})
		}
		c.logger.Debugf("Error parsing Version Negotiation packet: %s", err)
		return nil
	}

	// The Source Connection ID must echo the Destination Connection ID of our Initial.
	if !bytes.Equal(src, c.origDestConnID.Bytes()) {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header:  qlog.PacketHeader{PacketType: qlog.PacketTypeVersionNegotiation},
				Raw:     qlog.RawInfo{Length: int(p.Size()), PayloadLength: qlog.OmitLength},
				Trigger: qlog.PacketDropUnexpectedSourceConnectionID,
			})
		}
		c.logger.Debugf("Ignoring Version Negotiation packet with unexpected source connection ID: %s (expected %s)", src, c.origDestConnID)
		return nil
	}

	if slices.Contains(supportedVersions, c.version) {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header:  qlog.PacketHeader{PacketType: qlog.PacketTypeVersionNegotiation},
				Raw:     qlog.RawInfo{Length: int(p.Size()), PayloadLength: qlog.OmitLength},
				Trigger: qlog.PacketDropUnexpectedVersion,
			})
		}

		return nil
	}

	c.logger.Infof("Received a Version Negotiation packet. Supported Versions: %s", supportedVersions)
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.VersionNegotiationReceived{
			Header: qlog.PacketHeaderVersionNegotiation{
				DestConnectionID: dest,
				SrcConnectionID:  src,
			},
			SupportedVersions: supportedVersions,
		})
	}
	newVersion, ok := protocol.ChooseSupportedVersion(c.config.Versions, supportedVersions)
	if !ok {
		c.destroyImpl(&VersionNegotiationError{
			Ours:   c.config.Versions,
			Theirs: supportedVersions,
		})
		c.logger.Infof("No compatible QUIC version found.")
		return nil
	}
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.VersionInformation{
			ChosenVersion:  newVersion,
			ClientVersions: c.config.Versions,
			ServerVersions: supportedVersions,
		})
	}

	c.logger.Infof("Switching to QUIC version %s.", newVersion)
	nextPN, _ := c.sentPacketHandler.PeekPacketNumber(protocol.PacketNumberSpaceInitial)
	return &errCloseForRecreating{
		nextPacketNumber: nextPN,
		nextVersion:      newVersion,
	}
}

func (c *Conn) handleUnpackedLongHeaderPacket(
	packet *unpackedPacket,
	ecn protocol.ECN,
	rcvTime monotime.Time,
	datagramPayloadChecksum qlog.DatagramPayloadChecksum,
	packetSize protocol.ByteCount,
) error {
	if !c.receivedFirstPacket {
		c.receivedFirstPacket = true
		if !c.versionNegotiated && c.qlogger != nil {
			var clientVersions, serverVersions []Version
			switch c.perspective {
			case protocol.PerspectiveClient:
				clientVersions = c.config.Versions
			case protocol.PerspectiveServer:
				serverVersions = c.config.Versions
			}
			c.qlogger.RecordEvent(qlog.VersionInformation{
				ChosenVersion:  c.version,
				ClientVersions: clientVersions,
				ServerVersions: serverVersions,
			})
		}

		if c.perspective == protocol.PerspectiveClient && packet.hdr.SrcConnectionID != c.handshakeDestConnID {
			cid := packet.hdr.SrcConnectionID
			c.logger.Debugf("Received first packet. Switching destination connection ID to: %s", cid)
			c.handshakeDestConnID = cid
			c.connIDManager.ChangeInitialConnID(cid)
		}

		if c.perspective == protocol.PerspectiveServer {
			if packet.hdr.SrcConnectionID != c.handshakeDestConnID {
				c.handshakeDestConnID = packet.hdr.SrcConnectionID
				c.connIDManager.ChangeInitialConnID(packet.hdr.SrcConnectionID)
			}
			if c.qlogger != nil {
				var srcAddr, destAddr *net.UDPAddr
				if addr, ok := c.conn.LocalAddr().(*net.UDPAddr); ok {
					srcAddr = addr
				}
				if addr, ok := c.conn.RemoteAddr().(*net.UDPAddr); ok {
					destAddr = addr
				}
				c.qlogger.RecordEvent(startedConnectionEvent(srcAddr, destAddr))
			}
		}
	}

	if c.perspective == protocol.PerspectiveServer && packet.encryptionLevel == protocol.EncryptionHandshake &&
		!c.droppedInitialKeys {

		c.dropEncryptionLevel(protocol.EncryptionInitial, rcvTime)
	}

	c.lastPacketReceivedTime = rcvTime
	c.firstAckElicitingPacketAfterIdleSentTime = 0
	c.keepAlivePingSent = false

	if packet.hdr.Type == protocol.PacketType0RTT {
		c.largestRcvdAppData = max(c.largestRcvdAppData, packet.hdr.PacketNumber)
	}

	var log func([]qlog.Frame)
	if c.qlogger != nil {
		log = func(frames []qlog.Frame) {
			var token *qlog.Token
			if len(packet.hdr.Token) > 0 {
				token = &qlog.Token{Raw: packet.hdr.Token}
			}
			c.qlogger.RecordEvent(qlog.PacketReceived{
				Header: qlog.PacketHeader{
					PacketType:       toQlogPacketType(packet.hdr.Type),
					DestConnectionID: packet.hdr.DestConnectionID,
					SrcConnectionID:  packet.hdr.SrcConnectionID,
					PacketNumber:     packet.hdr.PacketNumber,
					Version:          packet.hdr.Version,
					Token:            token,
				},
				Raw: qlog.RawInfo{
					Length:        int(packetSize),
					PayloadLength: int(packet.hdr.Length),
				},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Frames:                  frames,
				ECN:                     toQlogECN(ecn),
			})
		}
	}
	isAckEliciting, _, _, err := c.handleFrames(packet.data, packet.hdr.DestConnectionID, packet.encryptionLevel, log, rcvTime)
	if err != nil {
		return err
	}
	c.sentPacketHandler.ReceivedPacket(packet.encryptionLevel, rcvTime)
	return c.receivedPacketHandler.ReceivedPacket(packet.hdr.PacketNumber, ecn, packet.encryptionLevel, rcvTime, isAckEliciting)
}

func (c *Conn) handleUnpackedShortHeaderPacket(
	destConnID protocol.ConnectionID,
	pn protocol.PacketNumber,
	data []byte,
	ecn protocol.ECN,
	rcvTime monotime.Time,
	log func([]qlog.Frame),
) (isNonProbing bool, pathChallenge *wire.PathChallengeFrame, _ error) {
	c.lastPacketReceivedTime = rcvTime
	c.firstAckElicitingPacketAfterIdleSentTime = 0
	c.keepAlivePingSent = false

	isAckEliciting, isNonProbing, pathChallenge, err := c.handleFrames(data, destConnID, protocol.Encryption1RTT, log, rcvTime)
	if err != nil {
		return false, nil, err
	}
	c.sentPacketHandler.ReceivedPacket(protocol.Encryption1RTT, rcvTime)
	if err := c.receivedPacketHandler.ReceivedPacket(pn, ecn, protocol.Encryption1RTT, rcvTime, isAckEliciting); err != nil {
		return false, nil, err
	}
	return isNonProbing, pathChallenge, nil
}

func (c *Conn) handleFrames(
	data []byte,
	destConnID protocol.ConnectionID,
	encLevel protocol.EncryptionLevel,
	log func([]qlog.Frame),
	rcvTime monotime.Time,
) (isAckEliciting, isNonProbing bool, pathChallenge *wire.PathChallengeFrame, _ error) {
	var frames []qlog.Frame
	if log != nil {
		frames = make([]qlog.Frame, 0, 4)
	}
	handshakeWasComplete := c.handshakeComplete
	var handleErr error
	var skipHandling bool

	for len(data) > 0 {
		frameType, l, err := c.frameParser.ParseType(data, encLevel)
		if err != nil {

			if err == io.EOF {
				break
			}
			return false, false, nil, err
		}
		data = data[l:]

		if ackhandler.IsFrameTypeAckEliciting(frameType) {
			isAckEliciting = true
		}
		if !wire.IsProbingFrameType(frameType) {
			isNonProbing = true
		}

		if frameType.IsStreamFrameType() {
			streamFrame, l, err := c.frameParser.ParseStreamFrame(frameType, data, c.version)
			if err != nil {
				return false, false, nil, err
			}
			data = data[l:]

			if log != nil {
				frames = append(frames, toQlogFrame(streamFrame))
			}

			if skipHandling {
				continue
			}
			wire.LogFrame(c.logger, streamFrame, false)
			handleErr = c.streamsMap.HandleStreamFrame(streamFrame, rcvTime)
		} else if frameType.IsAckFrameType() {
			ackFrame, l, err := c.frameParser.ParseAckFrame(frameType, data, encLevel, c.version)
			if err != nil {
				return false, false, nil, err
			}
			data = data[l:]
			if log != nil {
				frames = append(frames, toQlogFrame(ackFrame))
			}

			if skipHandling {
				continue
			}
			wire.LogFrame(c.logger, ackFrame, false)
			handleErr = c.handleAckFrame(ackFrame, encLevel, rcvTime)
		} else if frameType.IsDatagramFrameType() {
			datagramFrame, l, err := c.frameParser.ParseDatagramFrame(frameType, data, c.version)
			if err != nil {
				return false, false, nil, err
			}
			data = data[l:]

			if log != nil {
				frames = append(frames, toQlogFrame(datagramFrame))
			}

			if skipHandling {
				continue
			}
			wire.LogFrame(c.logger, datagramFrame, false)
			handleErr = c.handleDatagramFrame(datagramFrame)
		} else {
			frame, l, err := c.frameParser.ParseLessCommonFrame(frameType, data, c.version)
			if err != nil {
				return false, false, nil, err
			}
			data = data[l:]

			if log != nil {
				frames = append(frames, toQlogFrame(frame))
			}

			if skipHandling {
				continue
			}
			pc, err := c.handleFrame(frame, encLevel, destConnID, rcvTime)
			if pc != nil {
				pathChallenge = pc
			}
			handleErr = err
		}

		if handleErr != nil {

			skipHandling = true
			if log == nil {
				return false, false, nil, handleErr
			}
		}
	}

	if log != nil {
		log(frames)
		if handleErr != nil {
			return false, false, nil, handleErr
		}
	}

	if !handshakeWasComplete && c.handshakeComplete {
		if err := c.handleHandshakeComplete(rcvTime); err != nil {
			return false, false, nil, err
		}
	}
	return
}

func (c *Conn) handleFrame(
	f wire.Frame,
	encLevel protocol.EncryptionLevel,
	destConnID protocol.ConnectionID,
	rcvTime monotime.Time,
) (pathChallenge *wire.PathChallengeFrame, _ error) {
	var err error
	wire.LogFrame(c.logger, f, false)
	switch frame := f.(type) {
	case *wire.CryptoFrame:
		err = c.handleCryptoFrame(frame, encLevel, rcvTime)
	case *wire.ConnectionCloseFrame:
		err = c.handleConnectionCloseFrame(frame)
	case *wire.ResetStreamFrame:
		err = c.streamsMap.HandleResetStreamFrame(frame, rcvTime)
	case *wire.MaxDataFrame:
		c.connFlowController.UpdateSendWindow(frame.MaximumData)
	case *wire.MaxStreamDataFrame:
		err = c.streamsMap.HandleMaxStreamDataFrame(frame)
	case *wire.MaxStreamsFrame:
		c.streamsMap.HandleMaxStreamsFrame(frame)
	case *wire.DataBlockedFrame:
	case *wire.StreamDataBlockedFrame:
		err = c.streamsMap.HandleStreamDataBlockedFrame(frame)
	case *wire.StreamsBlockedFrame:
	case *wire.StopSendingFrame:
		err = c.streamsMap.HandleStopSendingFrame(frame)
	case *wire.PingFrame:
	case *wire.PathChallengeFrame:
		pathChallenge = frame
	case *wire.PathResponseFrame:
		err = c.handlePathResponseFrame(frame)
	case *wire.NewTokenFrame:
		err = c.handleNewTokenFrame(frame)
	case *wire.NewConnectionIDFrame:
		err = c.connIDManager.Add(frame)
	case *wire.RetireConnectionIDFrame:
		err = c.connIDGenerator.Retire(frame.SequenceNumber, destConnID, rcvTime.Add(3*c.rttStats.PTO(false)))
	case *wire.HandshakeDoneFrame:
		err = c.handleHandshakeDoneFrame(rcvTime)
	default:
		err = fmt.Errorf("unexpected frame type: %s", reflect.ValueOf(&frame).Elem().Type().Name())
	}
	return pathChallenge, err
}

// queuePacket queues a packet received by the pathReceiver source,
// i.e. on the Transport that source is registered with.
func (c *Conn) queuePacket(p receivedPacket, source *pathReceiver) {
	// Discard packets once the amount of queued packets is larger than
	// the channel size, protocol.MaxConnUnprocessedPackets
	if !c.receivedPackets.Push(p, source) {
		if c.qlogger != nil {
			var datagramPayloadChecksum qlog.DatagramPayloadChecksum
			if wire.IsLongHeaderPacket(p.data[0]) {
				datagramPayloadChecksum = qlog.CalculateDatagramPayloadChecksum(p.data)
			}
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Raw:                     qlog.RawInfo{Length: int(p.Size()), PayloadLength: qlog.OmitLength},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropDOSPrevention,
			})
		}
		return
	}

	select {
	case c.notifyReceivedPacket <- struct{}{}:
	default:
	}
}

func (c *Conn) handleConnectionCloseFrame(frame *wire.ConnectionCloseFrame) error {
	if frame.IsApplicationError {
		return &qerr.ApplicationError{
			Remote:       true,
			ErrorCode:    qerr.ApplicationErrorCode(frame.ErrorCode),
			ErrorMessage: frame.ReasonPhrase,
		}
	}
	return &qerr.TransportError{
		Remote:       true,
		ErrorCode:    qerr.TransportErrorCode(frame.ErrorCode),
		FrameType:    frame.FrameType,
		ErrorMessage: frame.ReasonPhrase,
	}
}

func (c *Conn) handleCryptoFrame(frame *wire.CryptoFrame, encLevel protocol.EncryptionLevel, rcvTime monotime.Time) error {
	if err := c.cryptoStreamManager.HandleCryptoFrame(frame, encLevel); err != nil {
		return err
	}
	for {
		data := c.cryptoStreamManager.GetCryptoData(encLevel)
		if data == nil {
			break
		}
		if err := c.cryptoStreamHandler.HandleMessage(data, encLevel); err != nil {
			return err
		}
	}
	return c.handleHandshakeEvents(rcvTime)
}

func (c *Conn) handleHandshakeEvents(now monotime.Time) error {
	for {
		ev := c.cryptoStreamHandler.NextEvent()
		var err error
		switch ev.Kind {
		case handshake.EventNoEvent:
			return nil
		case handshake.EventHandshakeComplete:

			c.handshakeComplete = true
		case handshake.EventReceivedTransportParameters:
			err = c.handleTransportParameters(ev.TransportParameters)
		case handshake.EventRestoredTransportParameters:
			c.restoreTransportParameters(ev.TransportParameters)
			close(c.earlyConnReadyChan)
		case handshake.EventReceived0RTTReadKeys,
			handshake.EventReceivedHandshakeReadKeys,
			handshake.EventReceived1RTTReadKeys:
			//nolint:exhaustive
			switch ev.Kind {
			case handshake.EventReceivedHandshakeReadKeys:
				err = c.cryptoStreamManager.Finish(protocol.EncryptionInitial)
			case handshake.EventReceived1RTTReadKeys:
				err = c.cryptoStreamManager.Finish(protocol.EncryptionHandshake)
			}

			c.undecryptablePacketsToProcess = append(c.undecryptablePacketsToProcess, c.undecryptablePackets...)
			c.undecryptablePackets = nil
		case handshake.EventDiscard0RTTKeys:
			c.dropEncryptionLevel(protocol.Encryption0RTT, now)
		case handshake.EventWriteInitialData:
			_, err = c.initialStream.Write(ev.Data)
		case handshake.EventWriteHandshakeData:
			_, err = c.handshakeStream.Write(ev.Data)
		}
		if err != nil {
			return err
		}
	}
}

// handlePathChallengeFrame sends the PATH_RESPONSE on the path that the PATH_CHALLENGE was received on.
func (c *Conn) handlePathChallengeFrame(f *wire.PathChallengeFrame, path pathID, now monotime.Time) error {
	resp := &wire.PathResponseFrame{Data: f.Data}
	if path == activePathID {
		c.queueControlFrame(resp)
		return nil
	}
	// The Transport is unknown for the path that the connection was dialed on, and for closed paths.
	// The PATH_RESPONSE is then sent on the active path, which violates RFC 9000, Section 8.2.2.
	// TODO: drop the PATH_CHALLENGE once closing a path unregisters its pathReceiver.
	tr, ok := c.getPathManager().Transport(path)
	if !ok {
		c.queueControlFrame(resp)
		return nil
	}
	// the response is sent directly, so enforce the send loop's limit on tracked packets
	if c.sentPacketHandler.SendMode(now) == ackhandler.SendNone {
		return nil
	}
	connID, ok := c.connIDManager.GetConnIDForPath(path)
	if !ok {
		return nil
	}
	probe, buf, err := c.packer.PackPathProbePacket(connID, []ackhandler.Frame{{Frame: resp, Handler: emptyHandler{}}}, c.version)
	if err != nil {
		return err
	}
	c.logShortHeaderPacketWithDatagramPayloadChecksum(probe, protocol.ECNNon, buf.Len(), false, 0, strconv.FormatInt(int64(path), 10))
	c.registerPackedShortHeaderPacket(probe, protocol.ECNNon, now)
	tr.WriteTo(buf.Data, c.conn.RemoteAddr())
	return nil
}

func (c *Conn) handlePathResponseFrame(f *wire.PathResponseFrame) error {
	switch c.perspective {
	case protocol.PerspectiveClient:
		return c.handlePathResponseFrameClient(f)
	case protocol.PerspectiveServer:
		return c.handlePathResponseFrameServer(f)
	default:
		panic("unreachable")
	}
}

func (c *Conn) handlePathResponseFrameClient(f *wire.PathResponseFrame) error {
	pm := c.pathManagerOutgoing.Load()
	if pm == nil {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "unexpected PATH_RESPONSE frame",
		}
	}
	pm.HandlePathResponseFrame(f)
	return nil
}

func (c *Conn) handlePathResponseFrameServer(f *wire.PathResponseFrame) error {
	if c.pathManager == nil {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "unexpected PATH_RESPONSE frame",
		}
	}
	c.pathManager.HandlePathResponseFrame(f)
	return nil
}

func (c *Conn) handleNewTokenFrame(frame *wire.NewTokenFrame) error {
	if c.perspective == protocol.PerspectiveServer {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received NEW_TOKEN frame from the client",
		}
	}
	if c.config.TokenStore != nil {
		c.config.TokenStore.Put(c.tokenStoreKey, &ClientToken{data: frame.Token, rtt: c.rttStats.SmoothedRTT()})
	}
	return nil
}

func (c *Conn) handleHandshakeDoneFrame(rcvTime monotime.Time) error {
	if c.perspective == protocol.PerspectiveServer {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received a HANDSHAKE_DONE frame",
		}
	}
	if !c.handshakeConfirmed {
		return c.handleHandshakeConfirmed(rcvTime)
	}
	return nil
}

func (c *Conn) handleAckFrame(frame *wire.AckFrame, encLevel protocol.EncryptionLevel, rcvTime monotime.Time) error {
	acked1RTTPacket, err := c.sentPacketHandler.ReceivedAck(frame, encLevel, c.lastPacketReceivedTime)
	if err != nil {
		return err
	}
	if !acked1RTTPacket {
		return nil
	}

	if c.perspective == protocol.PerspectiveClient && !c.handshakeConfirmed {
		if err := c.handleHandshakeConfirmed(rcvTime); err != nil {
			return err
		}
	}

	if c.mtuDiscoverer != nil {
		mtu := c.mtuDiscoverer.CurrentSize()
		maxPayloadSize := estimateMaxPayloadSize(mtu)
		if maxPayloadSize > protocol.ByteCount(c.maxPayloadSizeEstimate.Load()) {
			c.maxPayloadSizeEstimate.Store(uint32(maxPayloadSize))
			c.sentPacketHandler.SetMaxDatagramSize(mtu)
		}
	}
	return c.cryptoStreamHandler.SetLargest1RTTAcked(frame.LargestAcked())
}

func (c *Conn) handleDatagramFrame(f *wire.DatagramFrame) error {
	if f.Length(c.version) > wire.MaxDatagramSize {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "DATAGRAM frame too large",
		}
	}
	c.datagramQueue.HandleDatagramFrame(f)
	return nil
}

func (c *Conn) setCloseError(e *closeError) {
	c.closeErr.CompareAndSwap(nil, e)
	select {
	case c.closeChan <- struct{}{}:
	default:
	}
}

func (c *Conn) closeLocal(e error) {
	c.setCloseError(&closeError{err: e, immediate: false})
}

func (c *Conn) destroy(e error) {
	c.destroyImpl(e)
	<-c.ctx.Done()
}

func (c *Conn) destroyImpl(e error) {
	c.setCloseError(&closeError{err: e, immediate: true})
}

func (c *Conn) CloseWithError(code ApplicationErrorCode, desc string) error {
	c.closeLocal(&qerr.ApplicationError{
		ErrorCode:    code,
		ErrorMessage: desc,
	})
	<-c.ctx.Done()
	return nil
}

func (c *Conn) closeWithTransportError(code TransportErrorCode) {
	c.closeLocal(&qerr.TransportError{ErrorCode: code})
	<-c.ctx.Done()
}

func (c *Conn) handleCloseError(closeErr *closeError) {
	if closeErr.immediate {
		if nerr, ok := closeErr.err.(net.Error); ok && nerr.Timeout() {
			c.logger.Errorf("Destroying connection: %s", closeErr.err)
		} else {
			c.logger.Errorf("Destroying connection with error: %s", closeErr.err)
		}
	} else {
		if closeErr.err == nil {
			c.logger.Infof("Closing connection.")
		} else {
			c.logger.Errorf("Closing connection with error: %s", closeErr.err)
		}
	}

	e := closeErr.err
	if e == nil {
		e = &qerr.ApplicationError{}
	} else {
		defer func() { closeErr.err = e }()
	}

	var (
		statelessResetErr     *StatelessResetError
		versionNegotiationErr *VersionNegotiationError
		recreateErr           *errCloseForRecreating
		applicationErr        *ApplicationError
		transportErr          *TransportError
	)
	var isRemoteClose bool
	var trigger qlog.ConnectionCloseTrigger
	var reason string
	var transportErrorCode *qlog.TransportErrorCode
	var applicationErrorCode *qlog.ApplicationErrorCode
	switch {
	case errors.Is(e, qerr.ErrIdleTimeout),
		errors.Is(e, qerr.ErrHandshakeTimeout):
		trigger = qlog.ConnectionCloseTriggerIdleTimeout
	case errors.As(e, &statelessResetErr):
		trigger = qlog.ConnectionCloseTriggerStatelessReset
	case errors.As(e, &versionNegotiationErr):
		trigger = qlog.ConnectionCloseTriggerVersionMismatch
	case errors.As(e, &recreateErr):
	case errors.As(e, &applicationErr):
		isRemoteClose = applicationErr.Remote
		reason = applicationErr.ErrorMessage
		applicationErrorCode = &applicationErr.ErrorCode
	case errors.As(e, &transportErr):
		isRemoteClose = transportErr.Remote
		reason = transportErr.ErrorMessage
		transportErrorCode = &transportErr.ErrorCode
	case closeErr.immediate:
		e = closeErr.err
	default:
		te := &qerr.TransportError{
			ErrorCode:    qerr.InternalError,
			ErrorMessage: e.Error(),
		}
		e = te
		reason = te.ErrorMessage
		code := te.ErrorCode
		transportErrorCode = &code
	}

	c.streamsMap.CloseWithError(e)
	if c.datagramQueue != nil {
		c.datagramQueue.CloseWithError(e)
	}

	defer c.connIDManager.Close()

	if c.qlogger != nil && !errors.As(e, &recreateErr) {
		initiator := qlog.InitiatorLocal
		if isRemoteClose {
			initiator = qlog.InitiatorRemote
		}
		c.qlogger.RecordEvent(qlog.ConnectionClosed{
			Initiator:        initiator,
			ConnectionError:  transportErrorCode,
			ApplicationError: applicationErrorCode,
			Trigger:          trigger,
			Reason:           reason,
		})
	}

	if isRemoteClose {
		c.connIDGenerator.ReplaceWithClosed(nil, 3*c.rttStats.PTO(false))
		return
	}
	if closeErr.immediate {
		c.connIDGenerator.RemoveAll()
		return
	}

	if c.perspective == protocol.PerspectiveClient && !c.sentFirstPacket {
		c.connIDGenerator.RemoveAll()
		return
	}
	connClosePacket, err := c.sendConnectionClose(e)
	if err != nil {
		c.logger.Debugf("Error sending CONNECTION_CLOSE: %s", err)
	}
	c.connIDGenerator.ReplaceWithClosed(connClosePacket, 3*c.rttStats.PTO(false))
}

func (c *Conn) dropEncryptionLevel(encLevel protocol.EncryptionLevel, now monotime.Time) {
	c.sentPacketHandler.DropPackets(encLevel, now)
	c.receivedPacketHandler.DropPackets(encLevel)
	//nolint:exhaustive
	switch encLevel {
	case protocol.EncryptionInitial:
		c.droppedInitialKeys = true
		c.cryptoStreamHandler.DiscardInitialKeys()
	case protocol.Encryption0RTT:
		c.streamsMap.ResetFor0RTT()
		c.framer.Handle0RTTRejection()
		c.connFlowController.Reset()
	}
}

func (c *Conn) restoreTransportParameters(params *wire.TransportParameters) {
	if c.logger.Debug() {
		c.logger.Debugf("Restoring Transport Parameters: %s", params)
	}
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.ParametersSet{
			Restore:                         true,
			Initiator:                       qlog.InitiatorRemote,
			SentBy:                          c.perspective,
			OriginalDestinationConnectionID: params.OriginalDestinationConnectionID,
			InitialSourceConnectionID:       params.InitialSourceConnectionID,
			RetrySourceConnectionID:         params.RetrySourceConnectionID,
			StatelessResetToken:             params.StatelessResetToken,
			DisableActiveMigration:          params.DisableActiveMigration,
			MaxIdleTimeout:                  params.MaxIdleTimeout,
			MaxUDPPayloadSize:               params.MaxUDPPayloadSize,
			AckDelayExponent:                params.AckDelayExponent,
			MaxAckDelay:                     params.MaxAckDelay,
			ActiveConnectionIDLimit:         params.ActiveConnectionIDLimit,
			InitialMaxData:                  params.InitialMaxData,
			InitialMaxStreamDataBidiLocal:   params.InitialMaxStreamDataBidiLocal,
			InitialMaxStreamDataBidiRemote:  params.InitialMaxStreamDataBidiRemote,
			InitialMaxStreamDataUni:         params.InitialMaxStreamDataUni,
			InitialMaxStreamsBidi:           int64(params.MaxBidiStreamNum),
			InitialMaxStreamsUni:            int64(params.MaxUniStreamNum),
			MaxDatagramFrameSize:            params.MaxDatagramFrameSize,
			EnableResetStreamAt:             params.EnableResetStreamAt,
		})
	}

	c.peerParams = params
	c.connIDGenerator.SetMaxActiveConnIDs(params.ActiveConnectionIDLimit)
	c.connFlowController.UpdateSendWindow(params.InitialMaxData)
	c.streamsMap.HandleTransportParameters(params)
}

func (c *Conn) handleTransportParameters(params *wire.TransportParameters) error {
	if c.qlogger != nil {
		c.qlogTransportParameters(params, c.perspective.Opposite(), false)
	}
	if err := c.checkTransportParameters(params); err != nil {
		return &qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: err.Error(),
		}
	}

	if c.perspective == protocol.PerspectiveClient && c.peerParams != nil && c.ConnectionState().Used0RTT && !params.ValidForUpdate(c.peerParams) {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "server sent reduced limits after accepting 0-RTT data",
		}
	}

	c.peerParams = params

	if c.perspective == protocol.PerspectiveServer {
		c.applyTransportParameters()

		close(c.earlyConnReadyChan)
	}
	return nil
}

func (c *Conn) checkTransportParameters(params *wire.TransportParameters) error {
	if c.logger.Debug() {
		c.logger.Debugf("Processed Transport Parameters: %s", params)
	}

	if params.InitialSourceConnectionID != c.handshakeDestConnID {
		return fmt.Errorf("expected initial_source_connection_id to equal %s, is %s", c.handshakeDestConnID, params.InitialSourceConnectionID)
	}

	if c.perspective == protocol.PerspectiveServer {
		return nil
	}

	if params.OriginalDestinationConnectionID != c.origDestConnID {
		return fmt.Errorf("expected original_destination_connection_id to equal %s, is %s", c.origDestConnID, params.OriginalDestinationConnectionID)
	}
	if c.retrySrcConnID != nil {
		if params.RetrySourceConnectionID == nil {
			return errors.New("missing retry_source_connection_id")
		}
		if *params.RetrySourceConnectionID != *c.retrySrcConnID {
			return fmt.Errorf("expected retry_source_connection_id to equal %s, is %s", c.retrySrcConnID, *params.RetrySourceConnectionID)
		}
	} else if params.RetrySourceConnectionID != nil {
		return errors.New("received retry_source_connection_id, although no Retry was performed")
	}
	return nil
}

func (c *Conn) applyTransportParameters() {
	params := c.peerParams

	c.idleTimeout = c.config.MaxIdleTimeout

	if params.MaxIdleTimeout > 0 {
		c.idleTimeout = min(c.idleTimeout, params.MaxIdleTimeout)
	}
	c.keepAliveInterval = min(c.config.KeepAlivePeriod, c.idleTimeout/2)
	c.streamsMap.HandleTransportParameters(params)
	c.frameParser.SetAckDelayExponent(params.AckDelayExponent)
	c.connFlowController.UpdateSendWindow(params.InitialMaxData)
	c.rttStats.SetMaxAckDelay(params.MaxAckDelay)
	c.connIDGenerator.SetMaxActiveConnIDs(params.ActiveConnectionIDLimit)
	if params.StatelessResetToken != nil {
		c.connIDManager.SetStatelessResetToken(*params.StatelessResetToken)
	}

	if params.PreferredAddress != nil {
		c.connIDManager.AddFromPreferredAddress(params.PreferredAddress.ConnectionID, params.PreferredAddress.StatelessResetToken)
	}
	if c.mtuDiscoverer != nil {
		c.mtuDiscoverer = newMTUDiscoverer(c.rttStats, c.mtuDiscoverer.CurrentSize(), c.maxMTU(), c.qlogger)
	}
}

func (c *Conn) maxMTU() protocol.ByteCount {
	if c.peerParams == nil || c.peerParams.MaxUDPPayloadSize <= 0 {
		return protocol.MaxPacketBufferSize
	}
	return min(protocol.MaxPacketBufferSize, c.peerParams.MaxUDPPayloadSize)
}

func (c *Conn) triggerSending(now monotime.Time) error {
	c.pacingDeadline = 0

	sendMode := c.sentPacketHandler.SendMode(now)
	switch sendMode {
	case ackhandler.SendAny:
		return c.sendPackets(now)
	case ackhandler.SendNone:
		c.blocked = blockModeHardBlocked
		return nil
	case ackhandler.SendPacingLimited:
		deadline := c.sentPacketHandler.TimeUntilSend()
		if deadline.IsZero() {
			deadline = deadlineSendImmediately
		}
		c.pacingDeadline = deadline

		return c.maybeSendAckOnlyPacket(now)
	case ackhandler.SendAck:

		c.blocked = blockModeCongestionLimited
		return c.maybeSendAckOnlyPacket(now)
	case ackhandler.SendPTOInitial, ackhandler.SendPTOHandshake, ackhandler.SendPTOAppData:
		if err := c.sendProbePacket(sendMode, now); err != nil {
			return err
		}
		if c.sendQueue.WouldBlock() {
			c.scheduleSending()
			return nil
		}
		return c.triggerSending(now)
	default:
		return fmt.Errorf("BUG: invalid send mode %d", sendMode)
	}
}

func (c *Conn) sendPackets(now monotime.Time) error {
	if c.perspective == protocol.PerspectiveClient && c.handshakeConfirmed {
		if pm := c.pathManagerOutgoing.Load(); pm != nil {
			connID, frame, tr, ok := pm.NextPathToProbe()
			if ok {
				probe, buf, err := c.packer.PackPathProbePacket(connID, []ackhandler.Frame{frame}, c.version)
				if err != nil {
					return err
				}
				c.logger.Debugf("sending path probe packet from %s", c.LocalAddr())
				h, _ := c.connIDGenerator.Handler((*packetHandlerMap)(tr))
				c.logShortHeaderPacketWithDatagramPayloadChecksum(probe, protocol.ECNNon, buf.Len(), false, 0, strconv.FormatInt(int64(h.id), 10))
				c.registerPackedShortHeaderPacket(probe, protocol.ECNNon, now)
				tr.WriteTo(buf.Data, c.conn.RemoteAddr())

				c.scheduleSending()
				return nil
			}
		}
	}

	if c.handshakeConfirmed && c.mtuDiscoverer != nil && c.mtuDiscoverer.ShouldSendProbe(now) {
		ping, size := c.mtuDiscoverer.GetPing(now)
		p, buf, err := c.packer.PackMTUProbePacket(ping, size, c.version)
		if err != nil {
			return err
		}
		ecn := c.sentPacketHandler.ECNMode(true)
		c.logShortHeaderPacket(p, ecn, buf.Len())
		c.registerPackedShortHeaderPacket(p, ecn, now)
		c.sendQueue.Send(buf, 0, ecn)

		c.scheduleSending()
		return nil
	}

	if offset := c.connFlowController.GetWindowUpdate(now); offset > 0 {
		c.framer.QueueControlFrame(&wire.MaxDataFrame{MaximumData: offset})
	}
	if !c.handshakeConfirmed {
		packet, err := c.packer.PackCoalescedPacket(false, c.maxPacketSize(), now, c.version)
		if err != nil || packet == nil {
			return err
		}
		c.sentFirstPacket = true
		if err := c.sendPackedCoalescedPacket(packet, c.sentPacketHandler.ECNMode(packet.IsOnlyShortHeaderPacket()), now); err != nil {
			return err
		}
		//nolint:exhaustive
		switch c.sentPacketHandler.SendMode(now) {
		case ackhandler.SendPacingLimited:
			c.resetPacingDeadline()
		case ackhandler.SendAny:
			c.pacingDeadline = deadlineSendImmediately
		}
		return nil
	}

	if c.conn.capabilities().GSO {
		return c.sendPacketsWithGSO(now)
	}
	return c.sendPacketsWithoutGSO(now)
}

func (c *Conn) sendPacketsWithoutGSO(now monotime.Time) error {
	for {
		buf := getPacketBuffer()
		ecn := c.sentPacketHandler.ECNMode(true)
		if _, err := c.appendOneShortHeaderPacket(buf, c.maxPacketSize(), ecn, now); err != nil {
			if err == errNothingToPack {
				buf.Release()
				return nil
			}
			return err
		}

		c.sendQueue.Send(buf, 0, ecn)

		if c.sendQueue.WouldBlock() {
			return nil
		}
		sendMode := c.sentPacketHandler.SendMode(now)
		if sendMode == ackhandler.SendPacingLimited {
			c.resetPacingDeadline()
			return nil
		}
		if sendMode != ackhandler.SendAny {
			return nil
		}
		// Prioritize receiving of packets over sending out more packets.
		if !c.receivedPackets.Empty() {
			c.pacingDeadline = deadlineSendImmediately
			return nil
		}
	}
}

func (c *Conn) sendPacketsWithGSO(now monotime.Time) error {
	buf := getLargePacketBuffer()
	maxSize := c.maxPacketSize()

	ecn := c.sentPacketHandler.ECNMode(true)
	for {
		var dontSendMore bool
		size, err := c.appendOneShortHeaderPacket(buf, maxSize, ecn, now)
		if err != nil {
			if err != errNothingToPack {
				return err
			}
			if buf.Len() == 0 {
				buf.Release()
				return nil
			}
			dontSendMore = true
		}

		if !dontSendMore {
			sendMode := c.sentPacketHandler.SendMode(now)
			if sendMode == ackhandler.SendPacingLimited {
				c.resetPacingDeadline()
			}
			if sendMode != ackhandler.SendAny {
				dontSendMore = true
			}
		}

		nextECN := c.sentPacketHandler.ECNMode(true)

		if !dontSendMore && size == maxSize && nextECN == ecn && buf.Len()+maxSize <= buf.Cap() {
			continue
		}

		c.sendQueue.Send(buf, uint16(maxSize), ecn)

		if dontSendMore {
			return nil
		}
		if c.sendQueue.WouldBlock() {
			return nil
		}

		// Prioritize receiving of packets over sending out more packets.
		if !c.receivedPackets.Empty() {
			c.pacingDeadline = deadlineSendImmediately
			return nil
		}

		ecn = nextECN
		buf = getLargePacketBuffer()
	}
}

func (c *Conn) resetPacingDeadline() {
	deadline := c.sentPacketHandler.TimeUntilSend()
	if deadline.IsZero() {
		deadline = deadlineSendImmediately
	}
	c.pacingDeadline = deadline
}

func (c *Conn) maybeSendAckOnlyPacket(now monotime.Time) error {
	if !c.handshakeConfirmed {
		ecn := c.sentPacketHandler.ECNMode(false)
		packet, err := c.packer.PackCoalescedPacket(true, c.maxPacketSize(), now, c.version)
		if err != nil {
			return err
		}
		if packet == nil {
			return nil
		}
		return c.sendPackedCoalescedPacket(packet, ecn, now)
	}

	ecn := c.sentPacketHandler.ECNMode(true)
	p, buf, err := c.packer.PackAckOnlyPacket(c.maxPacketSize(), now, c.version)
	if err != nil {
		if err == errNothingToPack {
			return nil
		}
		return err
	}
	c.logShortHeaderPacket(p, ecn, buf.Len())
	c.registerPackedShortHeaderPacket(p, ecn, now)
	c.sendQueue.Send(buf, 0, ecn)
	return nil
}

func (c *Conn) sendProbePacket(sendMode ackhandler.SendMode, now monotime.Time) error {
	var encLevel protocol.EncryptionLevel
	//nolint:exhaustive
	switch sendMode {
	case ackhandler.SendPTOInitial:
		encLevel = protocol.EncryptionInitial
	case ackhandler.SendPTOHandshake:
		encLevel = protocol.EncryptionHandshake
	case ackhandler.SendPTOAppData:
		encLevel = protocol.Encryption1RTT
	default:
		return fmt.Errorf("connection BUG: unexpected send mode: %d", sendMode)
	}

	var packet *coalescedPacket
	for packet == nil {
		if wasQueued := c.sentPacketHandler.QueueProbePacket(encLevel.PacketNumberSpace()); !wasQueued {
			break
		}
		var err error
		packet, err = c.packer.PackPTOProbePacket(encLevel, c.maxPacketSize(), false, now, c.version)
		if err != nil {
			return err
		}
	}
	if packet == nil {
		var err error
		packet, err = c.packer.PackPTOProbePacket(encLevel, c.maxPacketSize(), true, now, c.version)
		if err != nil {
			return err
		}
	}
	if packet == nil || (len(packet.longHdrPackets) == 0 && packet.shortHdrPacket == nil) {
		return fmt.Errorf("connection BUG: couldn't pack %s probe packet: %v", encLevel, packet)
	}
	return c.sendPackedCoalescedPacket(packet, c.sentPacketHandler.ECNMode(packet.IsOnlyShortHeaderPacket()), now)
}

func (c *Conn) appendOneShortHeaderPacket(buf *packetBuffer, maxSize protocol.ByteCount, ecn protocol.ECN, now monotime.Time) (protocol.ByteCount, error) {
	startLen := buf.Len()
	p, err := c.packer.AppendPacket(buf, maxSize, now, c.version)
	if err != nil {
		return 0, err
	}
	size := buf.Len() - startLen
	c.logShortHeaderPacket(p, ecn, size)
	c.registerPackedShortHeaderPacket(p, ecn, now)
	return size, nil
}

func (c *Conn) registerPackedShortHeaderPacket(p shortHeaderPacket, ecn protocol.ECN, now monotime.Time) {
	if p.IsPathProbePacket {
		c.sentPacketHandler.SentPacket(
			now,
			p.PacketNumber,
			protocol.InvalidPacketNumber,
			p.StreamFrames,
			p.Frames,
			protocol.Encryption1RTT,
			ecn,
			p.Length,
			p.IsPathMTUProbePacket,
			true,
		)
		return
	}
	if c.firstAckElicitingPacketAfterIdleSentTime.IsZero() && (len(p.StreamFrames) > 0 || ackhandler.HasAckElicitingFrames(p.Frames)) {
		c.firstAckElicitingPacketAfterIdleSentTime = now
	}

	largestAcked := protocol.InvalidPacketNumber
	if p.Ack != nil {
		largestAcked = p.Ack.LargestAcked()
	}
	c.sentPacketHandler.SentPacket(
		now,
		p.PacketNumber,
		largestAcked,
		p.StreamFrames,
		p.Frames,
		protocol.Encryption1RTT,
		ecn,
		p.Length,
		p.IsPathMTUProbePacket,
		false,
	)
	c.connIDManager.SentPacket()
}

func (c *Conn) sendPackedCoalescedPacket(packet *coalescedPacket, ecn protocol.ECN, now monotime.Time) error {
	c.logCoalescedPacket(packet, ecn)
	for _, p := range packet.longHdrPackets {
		if c.firstAckElicitingPacketAfterIdleSentTime.IsZero() && p.IsAckEliciting() {
			c.firstAckElicitingPacketAfterIdleSentTime = now
		}
		largestAcked := protocol.InvalidPacketNumber
		if p.ack != nil {
			largestAcked = p.ack.LargestAcked()
		}
		c.sentPacketHandler.SentPacket(
			now,
			p.header.PacketNumber,
			largestAcked,
			p.streamFrames,
			p.frames,
			p.EncryptionLevel(),
			ecn,
			p.length,
			false,
			false,
		)
		if c.perspective == protocol.PerspectiveClient && p.EncryptionLevel() == protocol.EncryptionHandshake &&
			!c.droppedInitialKeys {

			c.dropEncryptionLevel(protocol.EncryptionInitial, now)
		}
	}
	if p := packet.shortHdrPacket; p != nil {
		if c.firstAckElicitingPacketAfterIdleSentTime.IsZero() && p.IsAckEliciting() {
			c.firstAckElicitingPacketAfterIdleSentTime = now
		}
		largestAcked := protocol.InvalidPacketNumber
		if p.Ack != nil {
			largestAcked = p.Ack.LargestAcked()
		}
		c.sentPacketHandler.SentPacket(
			now,
			p.PacketNumber,
			largestAcked,
			p.StreamFrames,
			p.Frames,
			protocol.Encryption1RTT,
			ecn,
			p.Length,
			p.IsPathMTUProbePacket,
			false,
		)
	}
	c.connIDManager.SentPacket()
	if c.mtuDiscoverer != nil {
		c.sendQueue.Send(packet.buffer, 0, ecn)
		return nil
	}

	packetSize := packet.buffer.Len()
	err := c.conn.Write(packet.buffer.Data, 0, ecn)
	packet.buffer.Release()
	if err != nil {
		if !isSendMsgSizeErr(err) || c.config.InitialPacketSize != 0 {
			return err
		}
	}
	initialPacketSize := c.config.initialPacketSize()
	if packetSize >= initialPacketSize {
		if err != nil {
			initialPacketSize = protocol.MinInitialPacketSize
			c.maxPayloadSizeEstimate.Store(uint32(estimateMaxPayloadSize(protocol.MinInitialPacketSize)))
			c.sentPacketHandler.SetMaxDatagramSize(protocol.MinInitialPacketSize)
		}
		c.mtuDiscoverer = newMTUDiscoverer(c.rttStats, initialPacketSize, c.maxMTU(), c.qlogger)
	}
	return nil
}

func (c *Conn) sendConnectionClose(e error) ([]byte, error) {
	var packet *coalescedPacket
	var err error
	if transportErr, ok := errors.AsType[*qerr.TransportError](e); ok {
		packet, err = c.packer.PackConnectionClose(transportErr, c.maxPacketSize(), c.version)
	} else if applicationErr, ok := errors.AsType[*qerr.ApplicationError](e); ok {
		packet, err = c.packer.PackApplicationClose(applicationErr, c.maxPacketSize(), c.version)
	} else {
		packet, err = c.packer.PackConnectionClose(&qerr.TransportError{
			ErrorCode:    qerr.InternalError,
			ErrorMessage: fmt.Sprintf("connection BUG: unspecified error type (msg: %s)", e.Error()),
		}, c.maxPacketSize(), c.version)
	}
	if err != nil {
		return nil, err
	}
	ecn := c.sentPacketHandler.ECNMode(packet.IsOnlyShortHeaderPacket())
	c.logCoalescedPacket(packet, ecn)
	return packet.buffer.Data, c.conn.Write(packet.buffer.Data, 0, ecn)
}

func (c *Conn) maxPacketSize() protocol.ByteCount {
	if c.perspective == protocol.PerspectiveServer && c.peerParams == nil {
		return protocol.MinInitialPacketSize
	}
	if c.mtuDiscoverer == nil {
		return c.config.initialPacketSize()
	}
	return c.mtuDiscoverer.CurrentSize()
}

func (c *Conn) AcceptStream(ctx context.Context) (*Stream, error) {
	return c.streamsMap.AcceptStream(ctx)
}

func (c *Conn) AcceptUniStream(ctx context.Context) (*ReceiveStream, error) {
	return c.streamsMap.AcceptUniStream(ctx)
}

func (c *Conn) OpenStream() (*Stream, error) {
	return c.streamsMap.OpenStream()
}

func (c *Conn) OpenStreamSync(ctx context.Context) (*Stream, error) {
	return c.streamsMap.OpenStreamSync(ctx)
}

func (c *Conn) OpenUniStream() (*SendStream, error) {
	return c.streamsMap.OpenUniStream()
}

func (c *Conn) OpenUniStreamSync(ctx context.Context) (*SendStream, error) {
	return c.streamsMap.OpenUniStreamSync(ctx)
}

func (c *Conn) newFlowController(id protocol.StreamID) *streamFlowController {
	initialSendWindow := c.peerParams.InitialMaxStreamDataUni
	if protocol.StreamTypeOf(id) == protocol.StreamTypeBidi {
		if protocol.StreamInitiator(id) == c.perspective {
			initialSendWindow = c.peerParams.InitialMaxStreamDataBidiRemote
		} else {
			initialSendWindow = c.peerParams.InitialMaxStreamDataBidiLocal
		}
	}
	return newStreamFlowController(
		id,
		c.connFlowController,
		protocol.ByteCount(c.config.InitialStreamReceiveWindow),
		protocol.ByteCount(c.config.MaxStreamReceiveWindow),
		initialSendWindow,
		c.rttStats,
		c.logger,
	)
}

func (c *Conn) scheduleSending() {
	select {
	case c.sendingScheduled <- struct{}{}:
	default:
	}
}

func (c *Conn) tryQueueingUndecryptablePacket(p receivedPacket, pt qlog.PacketType, datagramPayloadChecksum qlog.DatagramPayloadChecksum) {
	if c.handshakeComplete {
		panic("shouldn't queue undecryptable packets after handshake completion")
	}
	if len(c.undecryptablePackets)+1 > protocol.MaxUndecryptablePackets {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   pt,
					PacketNumber: protocol.InvalidPacketNumber,
				},
				Raw:                     qlog.RawInfo{Length: int(p.Size()), PayloadLength: qlog.OmitLength},
				DatagramPayloadChecksum: datagramPayloadChecksum,
				Trigger:                 qlog.PacketDropDOSPrevention,
			})
		}
		c.logger.Infof("Dropping undecryptable packet (%d bytes). Undecryptable packet queue full.", p.Size())
		return
	}
	c.logger.Infof("Queueing packet (%d bytes) for later decryption", p.Size())
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.PacketBuffered{
			Header: qlog.PacketHeader{
				PacketType:   pt,
				PacketNumber: protocol.InvalidPacketNumber,
			},
			Raw:                     qlog.RawInfo{Length: int(p.Size()), PayloadLength: qlog.OmitLength},
			DatagramPayloadChecksum: datagramPayloadChecksum,
		})
	}
	c.undecryptablePackets = append(c.undecryptablePackets, receivedPacketWithChecksum{receivedPacket: p, checksum: datagramPayloadChecksum})
}

func (c *Conn) queueControlFrame(f wire.Frame) {
	c.framer.QueueControlFrame(f)
	c.scheduleSending()
}

func (c *Conn) onHasConnectionData() { c.scheduleSending() }

func (c *Conn) onHasStreamData(id protocol.StreamID, str *SendStream) {
	c.framer.AddActiveStream(id, str)
	c.scheduleSending()
}

func (c *Conn) onHasStreamRetransmission(id protocol.StreamID, str *SendStream) {
	c.framer.AddStreamWithRetransmission(id, str)
	c.scheduleSending()
}

func (c *Conn) onHasStreamControlFrame(id protocol.StreamID, str streamControlFrameGetter) {
	c.framer.AddStreamWithControlFrames(id, str)
	c.scheduleSending()
}

func (c *Conn) onStreamCompleted(id protocol.StreamID) {
	if err := c.streamsMap.DeleteStream(id); err != nil {
		c.closeLocal(err)
	}
	c.framer.RemoveActiveStream(id)
}

func (c *Conn) onStreamCreditReleased(id protocol.StreamID) {
	c.streamsMap.ReleaseStreamCredit(id)
}

func (c *Conn) updateStreamPriority(id protocol.StreamID) {
	c.framer.UpdateStreamPriority(id)
	c.scheduleSending()
}

func (c *Conn) recordStreamPriorityUpdated(id protocol.StreamID, urgency int8, incremental bool) {
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.StreamPriorityUpdated{
			StreamID:    id,
			Urgency:     urgency,
			Incremental: incremental,
		})
	}
}

func (c *Conn) SendDatagram(p []byte) error {
	if !c.supportsDatagrams() {
		return errors.New("datagram support disabled")
	}

	f := &wire.DatagramFrame{DataLenPresent: true}

	maxDataLen := min(
		f.MaxDataLen(c.peerParams.MaxDatagramFrameSize, c.version),
		protocol.ByteCount(c.maxPayloadSizeEstimate.Load()),
	)
	if protocol.ByteCount(len(p)) > maxDataLen {
		return &DatagramTooLargeError{MaxDatagramPayloadSize: int64(maxDataLen)}
	}
	f.Data = make([]byte, len(p))
	copy(f.Data, p)
	return c.datagramQueue.Add(f)
}

func (c *Conn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if !c.config.EnableDatagrams {
		return nil, errors.New("datagram support disabled")
	}
	return c.datagramQueue.Receive(ctx)
}

func (c *Conn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *Conn) getPathManager() *pathManagerOutgoing {
	old := c.pathManagerOutgoing.Load()
	if old != nil {
		return old
	}

	new := newPathManagerOutgoing(
		c.connIDManager.GetConnIDForPath,
		c.connIDManager.RetireConnIDForPath,
		c.scheduleSending,
	)
	if c.pathManagerOutgoing.CompareAndSwap(old, new) {
		return new
	}

	return c.pathManagerOutgoing.Load()
}

func (c *Conn) AddPath(t *Transport) (*Path, error) {
	if c.perspective == protocol.PerspectiveServer {
		return nil, errors.New("server cannot initiate connection migration")
	}
	if c.peerParams.DisableActiveMigration {
		return nil, errors.New("server disabled connection migration")
	}
	if err := t.init(false); err != nil {
		return nil, err
	}
	return c.getPathManager().NewPath(
		t,
		200*time.Millisecond, // initial RTT estimate
		// Called on the run loop every time a PATH_CHALLENGE is sent on the Transport.
		// The pathReceiver is ignored if the connection is already registered with the Transport.
		func(id pathID) {
			r := &pathReceiver{Conn: c, id: id}
			if c.connIDGenerator.AddConnRunner((*packetHandlerMap)(t), r) && c.qlogger != nil {
				c.qlogger.RecordEvent(tupleAssignedEvent(strconv.FormatInt(int64(id), 10), t.Conn.LocalAddr(), c.conn.RemoteAddr()))
			}
		},
	), nil
}

func (c *Conn) HandshakeComplete() <-chan struct{} {
	return c.handshakeCompleteChan
}

func (c *Conn) QlogTrace() qlogwriter.Trace {
	return c.qlogTrace
}

func (c *Conn) NextConnection(ctx context.Context) (*Conn, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-c.Context().Done():
		return nil, context.Cause(c.Context())
	case <-c.HandshakeComplete():
		c.streamsMap.UseResetMaps()
		return c, nil
	}
}

func estimateMaxPayloadSize(mtu protocol.ByteCount) protocol.ByteCount {
	return mtu - 1 - 20 - 16
}
