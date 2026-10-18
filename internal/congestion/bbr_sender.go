package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

const (
	defaultMinimumCongestionWindow = protocol.ByteCount(protocol.InitialPacketSize << 2)
	defaultHighGain                = 2.885
	derivedHighCWNDGain            = 2.0
	defaultInitialRTT              = 100 * time.Millisecond
)

var PacingGain = [...]float64{1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}

const (
	gainCycleLength                             = len(PacingGain)
	bandwidthWindowSize                         = gainCycleLength + 2
	minRttExpiry                                = 10 * time.Second
	probeRttTime                                = 200 * time.Millisecond
	startupGrowthTarget                         = 1.25
	roundTripsWithoutGrowthBeforeExitingStartup = int64(6)
	defaultStartupFullLossCount                 = 8
	quicBbr2DefaultLossThreshold                = 0.05
	maxBbrBurstPackets                          = 3
)

type bbrMode int

const (
	bbrModeStartup = iota
	bbrModeDrain
	bbrModeProbeBw
	bbrModeProbeRtt
)

type bbrRecoveryState int

const (
	bbrRecoveryStateNotInRecovery = iota
	bbrRecoveryStateConservation
	bbrRecoveryStateGrowth
)

type bbrSender struct {
	rttStats  *utils.RTTStats
	connStats *utils.ConnectionStats
	clock     Clock
	rand      utils.Rand
	pacer     *pacer

	mode                              bbrMode
	sampler                           *bandwidthSampler
	roundTripCount                    roundTripCount
	currentRoundTripEnd               protocol.PacketNumber
	numLossEventsInRound              uint64
	bytesLostInRound                  protocol.ByteCount
	maxBandwidth                      *WindowedFilter[Bandwidth, roundTripCount]
	minRtt                            time.Duration
	minRttTimestamp                   monotime.Time
	congestionWindow                  protocol.ByteCount
	initialCongestionWindow           protocol.ByteCount
	maxCongestionWindow               protocol.ByteCount
	minCongestionWindow               protocol.ByteCount
	initialEstimateBandwidth          Bandwidth
	highGain                          float64
	highCwndGain                      float64
	drainGain                         float64
	pacingGain                        float64
	congestionWindowGain              float64
	congestionWindowGainConstant      float64
	numStartupRtts                    int64
	cycleCurrentOffset                int
	lastCycleStart                    monotime.Time
	isAtFullBandwidth                 bool
	roundsWithoutBandwidthGain        int64
	bandwidthAtLastRound              Bandwidth
	exitingQuiescence                 bool
	exitProbeRttAt                    monotime.Time
	probeRttRoundPassed               bool
	lastSampleIsAppLimited            bool
	recoveryState                     bbrRecoveryState
	endRecoveryAt                     protocol.PacketNumber
	recoveryWindow                    protocol.ByteCount
	enableAckAggregationDuringStartup bool
	expireAckAggregationInStartup     bool
	drainToTarget                     bool
	maxDatagramSize                   protocol.ByteCount
	maxPacingRate                     Bandwidth
	packetsAcked                      []protocol.PacketNumber
	packetsLost                       []protocol.PacketNumber
	bytesInFlight                     func() protocol.ByteCount
}

var (
	_ SendAlgorithm               = &bbrSender{}
	_ SendAlgorithmWithDebugInfos = &bbrSender{}
	_ HandleAggregatedAcks        = &bbrSender{}
)

func NewBbrSender(
	rttStats *utils.RTTStats,
	initialMaxDatagramSize protocol.ByteCount,
	maxPacingRate Bandwidth,
	bytesInFlight func() protocol.ByteCount,
	connStats *utils.ConnectionStats,
) *bbrSender {
	b := &bbrSender{
		rttStats:                          rttStats,
		connStats:                         connStats,
		clock:                             DefaultClock{},
		mode:                              bbrModeStartup,
		sampler:                           newBandwidthSampler(roundTripCount(bandwidthWindowSize)),
		currentRoundTripEnd:               protocol.InvalidPacketNumber,
		maxBandwidth:                      NewWindowedFilter(roundTripCount(bandwidthWindowSize), MaxFilter[Bandwidth]),
		congestionWindow:                  initialCongestionWindow * initialMaxDatagramSize,
		initialCongestionWindow:           initialCongestionWindow * initialMaxDatagramSize,
		maxCongestionWindow:               protocol.MaxCongestionWindowPackets * initialMaxDatagramSize,
		minCongestionWindow:               defaultMinimumCongestionWindow,
		initialEstimateBandwidth:          BandwidthFromDelta(initialCongestionWindow, defaultInitialRTT),
		highGain:                          defaultHighGain,
		highCwndGain:                      defaultHighGain,
		drainGain:                         1.0 / defaultHighGain,
		pacingGain:                        1.0,
		congestionWindowGain:              1.0,
		congestionWindowGainConstant:      2.0,
		numStartupRtts:                    roundTripsWithoutGrowthBeforeExitingStartup,
		recoveryState:                     bbrRecoveryStateNotInRecovery,
		endRecoveryAt:                     protocol.InvalidPacketNumber,
		recoveryWindow:                    protocol.MaxCongestionWindowPackets * initialMaxDatagramSize,
		enableAckAggregationDuringStartup: true,
		expireAckAggregationInStartup:     false,
		maxDatagramSize:                   initialMaxDatagramSize,
		maxPacingRate:                     maxPacingRate,
		packetsAcked:                      make([]protocol.PacketNumber, 0, 512),
		packetsLost:                       make([]protocol.PacketNumber, 0, 512),
		bytesInFlight:                     bytesInFlight,
	}
	b.pacer = newPacer()
	b.enterStartupMode(b.clock.Now())
	b.setHighCwndGain(derivedHighCWNDGain)
	b.updateConnectionStats()
	return b
}

func (b *bbrSender) TimeUntilSend(bytesInFlight protocol.ByteCount) monotime.Time {
	return b.pacer.TimeUntilSend(b.pacingRate())
}

func (b *bbrSender) HasPacingBudget(now monotime.Time) bool {
	return b.pacer.Budget(now, b.pacingRate()) >= b.maxDatagramSize
}

func (b *bbrSender) pacingRate() Bandwidth {
	bandwidth := Bandwidth(float64(b.bandwidthEstimate()) * b.pacingGain)
	return (Min(bandwidth, b.maxPacingRate) / BytesPerSecond * 11 / 10) * BytesPerSecond
}

func (b *bbrSender) OnPacketSent(sentTime monotime.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytesSent protocol.ByteCount, isRetransmittable bool) {
	b.pacer.SentPacket(sentTime, bytesSent, b.pacingRate())
	if bytesInFlight == 0 {
		b.exitingQuiescence = true
	}
	b.sampler.OnPacketSent(sentTime, bytesInFlight, packetNumber, bytesSent, isRetransmittable)
}

func (b *bbrSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

func (b *bbrSender) MaybeExitSlowStart() {}

func (b *bbrSender) OnPacketAcked(packetNumber protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time) {
	b.packetsAcked = append(b.packetsAcked, packetNumber)
}

func (b *bbrSender) OnAcksEnd(priorInFlight protocol.ByteCount, eventTime monotime.Time) {
	if len(b.packetsAcked) == 0 && len(b.packetsLost) == 0 {
		return
	}

	totalBytesAckedBefore := b.sampler.TotalBytesAcked()
	totalBytesLostBefore := b.sampler.TotalBytesLost()
	b.maybeAppLimited(priorInFlight)

	var isRoundStart bool
	if len(b.packetsAcked) > 0 {
		isRoundStart = b.updateRoundTripCounter(b.packetsAcked[len(b.packetsAcked)-1])
		b.updateRecoveryState(
			b.packetsAcked[len(b.packetsAcked)-1],
			len(b.packetsLost) > 0,
			isRoundStart,
		)
	}

	sample := b.sampler.OnAcksEnd(
		eventTime,
		b.packetsAcked,
		b.packetsLost,
		b.maxBandwidth.GetBest(),
		b.maxPacingRate,
		b.roundTripCount,
	)
	if sample.lastPacketSendState.isValid {
		b.lastSampleIsAppLimited = sample.lastPacketSendState.isAppLimited
		if sample.sampleMaxBandwidth >= b.maxPacingRate {
			b.lastSampleIsAppLimited = false
		}
	}

	if totalBytesAckedBefore != b.sampler.TotalBytesAcked() {
		if !sample.sampleIsAppLimited || sample.sampleMaxBandwidth > b.maxBandwidth.GetBest() {
			b.maxBandwidth.Update(sample.sampleMaxBandwidth, b.roundTripCount)
		}
	}

	var minRttExpired bool
	if sample.sampleRtt != infRTT {
		minRttExpired = b.maybeUpdateMinRtt(eventTime, sample.sampleRtt)
	}

	bytesAcked := b.sampler.TotalBytesAcked() - totalBytesAckedBefore
	bytesLost := b.sampler.TotalBytesLost() - totalBytesLostBefore
	excessAcked := sample.extraAcked
	lastPacketSendState := sample.lastPacketSendState

	if len(b.packetsLost) > 0 {
		b.numLossEventsInRound++
		b.bytesLostInRound += bytesLost
	}

	if b.mode == bbrModeProbeBw {
		b.updateGainCyclePhase(eventTime, priorInFlight, len(b.packetsLost) > 0)
	}
	if isRoundStart && !b.isAtFullBandwidth {
		b.checkIfFullBandwidthReached(&lastPacketSendState)
	}

	b.maybeExitStartupOrDrain(eventTime)
	b.maybeEnterOrExitProbeRtt(eventTime, isRoundStart, minRttExpired)
	b.calculateCongestionWindow(bytesAcked, excessAcked)
	b.calculateRecoveryWindow(bytesAcked, bytesLost)

	if len(b.packetsLost) > 0 {
		b.sampler.RemoveObsoletePackets(b.packetsLost[len(b.packetsLost)-1])
	}
	if len(b.packetsAcked) > 0 {
		bias := protocol.PacketNumber(b.calculateUselessAckBias())
		if uselessPacketNum := b.packetsAcked[0] - bias; uselessPacketNum > 0 {
			b.sampler.RemoveObsoletePackets(uselessPacketNum)
		}
	}
	if isRoundStart {
		b.numLossEventsInRound = 0
		b.bytesLostInRound = 0
	}

	b.packetsAcked = b.packetsAcked[:0]
	b.packetsLost = b.packetsLost[:0]
	b.updateConnectionStats()
}

func (b *bbrSender) updateConnectionStats() {
	if b.connStats != nil {
		b.connStats.CongestionWindow.Store(uint64(b.GetCongestionWindow()))
	}
}

func (b *bbrSender) OnCongestionEvent(packetNumber protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
	if lostBytes > 0 {
		b.packetsLost = append(b.packetsLost, packetNumber)
		if b.connStats != nil {
			b.connStats.PacketsLost.Add(1)
			b.connStats.BytesLost.Add(uint64(lostBytes))
		}
	}
}

func (b *bbrSender) OnRetransmissionTimeout(packetsRetransmitted bool) {}

func (b *bbrSender) OnSpuriousLoss(protocol.PacketNumber) {}

func (b *bbrSender) SetMaxDatagramSize(size protocol.ByteCount) {
	if size < b.maxDatagramSize {
		return
	}
	b.maxDatagramSize = size
	b.pacer.SetMaxDatagramSize(size)
}

func (b *bbrSender) InSlowStart() bool {
	return b.mode == bbrModeStartup
}

func (b *bbrSender) InRecovery() bool {
	return b.recoveryState != bbrRecoveryStateNotInRecovery
}

func (b *bbrSender) GetCongestionWindow() protocol.ByteCount {
	if b.mode == bbrModeProbeRtt {
		return b.probeRttCongestionWindow()
	}
	if b.InRecovery() && b.recoveryWindow > 0 {
		return Min(b.congestionWindow, b.recoveryWindow)
	}
	return b.congestionWindow
}

func (b *bbrSender) setHighCwndGain(highCwndGain float64) {
	b.highCwndGain = highCwndGain
	if b.mode == bbrModeStartup {
		b.congestionWindowGain = highCwndGain
	}
}

func (b *bbrSender) bandwidthEstimate() Bandwidth {
	rtt := b.rttStats.SmoothedRTT()
	if rtt == 0 {
		return b.maxPacingRate
	}

	bandwidth := b.maxBandwidth.GetBest()
	if bandwidth == 0 {
		return b.maxPacingRate
	}

	bandwidth = Max(bandwidth, b.initialEstimateBandwidth)
	bandwidth = Min(bandwidth, b.maxPacingRate)
	return bandwidth
}

func (b *bbrSender) getMinRtt() time.Duration {
	if b.minRtt != 0 {
		return b.minRtt
	}
	minRtt := b.rttStats.MinRTT()
	if minRtt != 0 {
		return minRtt
	}
	return defaultInitialRTT
}

func (b *bbrSender) getTargetCongestionWindow(gain float64) protocol.ByteCount {
	bdp := bdpFromRttAndBandwidth(b.getMinRtt(), b.bandwidthEstimate())
	congestionWindow := protocol.ByteCount(float64(bdp) * gain)
	if congestionWindow == 0 {
		congestionWindow = protocol.ByteCount(float64(b.initialCongestionWindow) * gain)
	}
	return Max(congestionWindow, b.minCongestionWindow)
}

func (b *bbrSender) probeRttCongestionWindow() protocol.ByteCount {
	return b.minCongestionWindow
}

func (b *bbrSender) maybeUpdateMinRtt(now monotime.Time, sampleMinRtt time.Duration) bool {
	minRttExpired := b.minRtt != 0 && now.After(b.minRttTimestamp.Add(minRttExpiry))
	if minRttExpired || sampleMinRtt < b.minRtt || b.minRtt == 0 {
		b.minRtt = sampleMinRtt
		b.minRttTimestamp = now
	}
	return minRttExpired
}

func (b *bbrSender) enterStartupMode(now monotime.Time) {
	b.mode = bbrModeStartup
	b.pacingGain = b.highGain
	b.congestionWindowGain = b.highCwndGain
}

func (b *bbrSender) enterProbeBandwidthMode(now monotime.Time) {
	b.mode = bbrModeProbeBw
	b.congestionWindowGain = b.congestionWindowGainConstant
	b.cycleCurrentOffset = int(b.rand.Uint32N(protocol.PacketsPerConnectionID)) % (gainCycleLength - 1)
	if b.cycleCurrentOffset >= 1 {
		b.cycleCurrentOffset += 1
	}
	b.lastCycleStart = now
	b.pacingGain = PacingGain[b.cycleCurrentOffset]
}

func (b *bbrSender) updateRoundTripCounter(lastAckedPacket protocol.PacketNumber) bool {
	if b.currentRoundTripEnd == protocol.InvalidPacketNumber || lastAckedPacket > b.currentRoundTripEnd {
		b.roundTripCount++
		b.currentRoundTripEnd = b.sampler.lastSentPacket
		return true
	}
	return false
}

func (b *bbrSender) updateGainCyclePhase(now monotime.Time, priorInFlight protocol.ByteCount, hasLosses bool) {
	shouldAdvanceGainCycling := now.After(b.lastCycleStart.Add(b.getMinRtt()))

	if b.pacingGain > 1.0 && !hasLosses && priorInFlight < b.getTargetCongestionWindow(b.pacingGain) {
		shouldAdvanceGainCycling = false
	}
	if b.pacingGain < 1.0 && b.bytesInFlight() <= b.getTargetCongestionWindow(1)*4/5 {
		shouldAdvanceGainCycling = true
	}

	if shouldAdvanceGainCycling {
		b.cycleCurrentOffset = (b.cycleCurrentOffset + 1) % gainCycleLength
		b.lastCycleStart = now
		if b.drainToTarget && b.pacingGain < 1 &&
			PacingGain[b.cycleCurrentOffset] == 1 &&
			b.bytesInFlight() > b.getTargetCongestionWindow(1) {
			return
		}
		b.pacingGain = PacingGain[b.cycleCurrentOffset]
	}
}

func (b *bbrSender) checkIfFullBandwidthReached(lastPacketSendState *sendTimeState) {
	if b.lastSampleIsAppLimited {
		return
	}

	bandwidth := b.bandwidthEstimate()
	target := Bandwidth(float64(b.bandwidthAtLastRound) * startupGrowthTarget)
	if bandwidth >= target {
		b.bandwidthAtLastRound = bandwidth
		b.roundsWithoutBandwidthGain = 0
		if b.expireAckAggregationInStartup {
			b.sampler.ResetMaxAckHeightTracker(0, b.roundTripCount)
		}
		return
	}

	b.roundsWithoutBandwidthGain++
	if b.roundsWithoutBandwidthGain >= b.numStartupRtts ||
		b.shouldExitStartupDueToLoss(lastPacketSendState) {
		b.isAtFullBandwidth = true
	}
}

func (b *bbrSender) maybeAppLimited(bytesInFlight protocol.ByteCount) {
	congestionWindow := b.GetCongestionWindow()
	if bytesInFlight >= congestionWindow {
		return
	}

	drainLimited := b.mode == bbrModeDrain && bytesInFlight > congestionWindow/2
	availableBytes := congestionWindow - bytesInFlight
	if !drainLimited || availableBytes > maxBbrBurstPackets*b.maxDatagramSize {
		b.sampler.OnAppLimited()
	}
}

func (b *bbrSender) maybeExitStartupOrDrain(now monotime.Time) {
	if b.mode == bbrModeStartup && b.isAtFullBandwidth {
		b.mode = bbrModeDrain
		b.pacingGain = b.drainGain
		b.congestionWindowGain = b.highCwndGain
	}
	if b.mode == bbrModeDrain && b.bytesInFlight() <= b.getTargetCongestionWindow(1) {
		b.roundsWithoutBandwidthGain = 0
		b.bandwidthAtLastRound = b.maxBandwidth.GetBest()
		b.enterProbeBandwidthMode(now)
	}
}

func (b *bbrSender) maybeEnterOrExitProbeRtt(now monotime.Time, isRoundStart, minRttExpired bool) {
	if minRttExpired && !b.exitingQuiescence && b.mode != bbrModeProbeRtt {
		b.mode = bbrModeProbeRtt
		b.pacingGain = 1.0
		b.exitProbeRttAt = monotime.Time(0)
	}

	if b.mode == bbrModeProbeRtt {
		b.sampler.OnAppLimited()
		if b.exitProbeRttAt.IsZero() {
			if b.bytesInFlight() < b.probeRttCongestionWindow()+protocol.MaxPacketBufferSize {
				b.exitProbeRttAt = now.Add(probeRttTime)
				b.probeRttRoundPassed = false
			}
		} else {
			if isRoundStart {
				b.probeRttRoundPassed = true
			}
			if now.Sub(b.exitProbeRttAt) >= 0 && b.probeRttRoundPassed {
				b.minRttTimestamp = now
				if !b.isAtFullBandwidth {
					b.enterStartupMode(now)
				} else {
					b.enterProbeBandwidthMode(now)
				}
			}
		}
	}
	b.exitingQuiescence = false
}

func (b *bbrSender) updateRecoveryState(lastAckedPacket protocol.PacketNumber, hasLosses, isRoundStart bool) {
	if !b.isAtFullBandwidth {
		return
	}
	if hasLosses {
		b.endRecoveryAt = b.sampler.lastSentPacket
	}

	switch b.recoveryState {
	case bbrRecoveryStateNotInRecovery:
		if hasLosses {
			b.recoveryState = bbrRecoveryStateConservation
			b.recoveryWindow = 0
			b.currentRoundTripEnd = b.sampler.lastSentPacket
		}
	case bbrRecoveryStateConservation:
		if isRoundStart {
			b.recoveryState = bbrRecoveryStateGrowth
		}
		fallthrough
	case bbrRecoveryStateGrowth:
		if !hasLosses && lastAckedPacket > b.endRecoveryAt {
			b.recoveryState = bbrRecoveryStateNotInRecovery
		}
	}
}

func (b *bbrSender) calculateCongestionWindow(bytesAcked, excessAcked protocol.ByteCount) {
	if b.mode == bbrModeProbeRtt {
		return
	}

	targetWindow := b.getTargetCongestionWindow(b.congestionWindowGain)
	if b.isAtFullBandwidth {
		targetWindow += b.sampler.MaxAckHeight()
	} else if b.enableAckAggregationDuringStartup {
		targetWindow += excessAcked
	}

	if b.isAtFullBandwidth {
		b.congestionWindow = Min(targetWindow, b.congestionWindow+bytesAcked)
	} else if b.congestionWindow < targetWindow ||
		b.sampler.TotalBytesAcked() < b.initialCongestionWindow {
		b.congestionWindow += bytesAcked
	}

	b.congestionWindow = Max(b.congestionWindow, b.minCongestionWindow)
	b.congestionWindow = Min(b.congestionWindow, b.maxCongestionWindow)
}

func (b *bbrSender) calculateRecoveryWindow(bytesAcked, bytesLost protocol.ByteCount) {
	if b.recoveryState == bbrRecoveryStateNotInRecovery {
		return
	}

	if b.recoveryWindow == 0 {
		b.recoveryWindow = b.bytesInFlight() + bytesAcked
		b.recoveryWindow = Max(b.recoveryWindow, b.minCongestionWindow)
		return
	}

	if b.recoveryWindow >= bytesLost {
		b.recoveryWindow -= bytesLost
	} else {
		b.recoveryWindow = b.maxDatagramSize
	}
	if b.recoveryState == bbrRecoveryStateGrowth {
		b.recoveryWindow += bytesAcked
	}

	b.recoveryWindow = Max(b.recoveryWindow, b.bytesInFlight()+bytesAcked)
	b.recoveryWindow = Max(b.recoveryWindow, b.minCongestionWindow)
}

func (b *bbrSender) shouldExitStartupDueToLoss(lastPacketSendState *sendTimeState) bool {
	if b.numLossEventsInRound < defaultStartupFullLossCount || !lastPacketSendState.isValid {
		return false
	}
	inflightAtSend := lastPacketSendState.bytesInFlight
	if inflightAtSend > 0 && b.bytesLostInRound > 0 {
		return b.bytesLostInRound > protocol.ByteCount(float64(inflightAtSend)*quicBbr2DefaultLossThreshold)
	}
	return false
}

func (b *bbrSender) calculateUselessAckBias() int64 {
	return int64(b.rttStats.PTO(false)) * int64(b.bandwidthEstimate()) / int64(protocol.InitialPacketSize*8) / int64(time.Second)
}

func bdpFromRttAndBandwidth(rtt time.Duration, bandwidth Bandwidth) protocol.ByteCount {
	return protocol.ByteCount(rtt) * protocol.ByteCount(bandwidth) / protocol.ByteCount(BytesPerSecond) / protocol.ByteCount(time.Second)
}
