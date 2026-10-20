package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

const (
	defaultHighGain     = 2.885
	derivedHighCWNDGain = 2.0
)

var PacingGain = [...]float64{1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}

const (
	gainCycleLength                             = len(PacingGain)
	bandwidthWindowSize                         = gainCycleLength + 2
	minRttExpiry                                = 10 * time.Second
	probeRttTime                                = 200 * time.Millisecond
	startupGrowthTarget                         = 1.25
	roundTripsWithoutGrowthBeforeExitingStartup = int64(3)
	defaultStartupFullLossCount                 = 8
	startupLossThreshold                        = 0.02
	startupPacingLimitThreshold                 = 0.95
	startupRoundsAtPacingLimit                  = 2
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
	rand      utils.Rand
	pacer     *bbrPacer

	mode                       bbrMode
	sampler                    *bandwidthSampler
	roundTripCount             roundTripCount
	currentRoundTripEnd        protocol.PacketNumber
	numLossEventsInRound       uint64
	bytesLostInRound           protocol.ByteCount
	maxBandwidth               *windowedFilter[Bandwidth]
	minRtt                     time.Duration
	minRttTimestamp            monotime.Time
	congestionWindow           protocol.ByteCount
	initialCongestionWindow    protocol.ByteCount
	maxCongestionWindow        protocol.ByteCount
	minCongestionWindow        protocol.ByteCount
	pacingRateValue            Bandwidth
	pacingGain                 float64
	congestionWindowGain       float64
	cycleCurrentOffset         int
	lastCycleStart             monotime.Time
	isAtFullBandwidth          bool
	roundsWithoutBandwidthGain int64
	bandwidthAtLastRound       Bandwidth
	exitingQuiescence          bool
	exitProbeRttAt             monotime.Time
	probeRttRoundPassed        bool
	lastSampleIsAppLimited     bool
	startupRoundStart          monotime.Time
	startupRoundBytesAcked     protocol.ByteCount
	startupRoundAppLimited     bool
	startupRoundPacingLimited  bool
	roundsAtPacingLimit        int
	recoveryState              bbrRecoveryState
	endRecoveryAt              protocol.PacketNumber
	recoveryWindow             protocol.ByteCount
	maxDatagramSize            protocol.ByteCount
	maxPacingRate              Bandwidth
	packetsAcked               []protocol.PacketNumber
	packetsLost                []protocol.PacketNumber
	bytesInFlight              func() protocol.ByteCount
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
		rttStats:                rttStats,
		connStats:               connStats,
		pacer:                   newBBRPacer(initialMaxDatagramSize),
		sampler:                 newBandwidthSampler(roundTripCount(bandwidthWindowSize)),
		currentRoundTripEnd:     protocol.InvalidPacketNumber,
		maxBandwidth:            newWindowedFilter[Bandwidth](roundTripCount(bandwidthWindowSize)),
		congestionWindow:        initialCongestionWindow * initialMaxDatagramSize,
		initialCongestionWindow: initialCongestionWindow * initialMaxDatagramSize,
		maxCongestionWindow:     protocol.MaxCongestionWindowPackets * initialMaxDatagramSize,
		minCongestionWindow:     4 * initialMaxDatagramSize,
		recoveryState:           bbrRecoveryStateNotInRecovery,
		endRecoveryAt:           protocol.InvalidPacketNumber,
		recoveryWindow:          protocol.MaxCongestionWindowPackets * initialMaxDatagramSize,
		maxDatagramSize:         initialMaxDatagramSize,
		maxPacingRate:           maxPacingRate,
		packetsAcked:            make([]protocol.PacketNumber, 0, 512),
		packetsLost:             make([]protocol.PacketNumber, 0, 512),
		bytesInFlight:           bytesInFlight,
	}
	b.enterStartupMode()
	b.updateConnectionStats()
	return b
}

func (b *bbrSender) TimeUntilSend(bytesInFlight protocol.ByteCount) monotime.Time {
	return b.pacer.TimeUntilSend(b.pacingRate())
}

func (b *bbrSender) HasPacingBudget(now monotime.Time) bool {
	rate := b.pacingRate()
	b.pacer.SetRate(now, rate)
	return b.pacer.Budget(now, rate) >= b.maxDatagramSize
}

func (b *bbrSender) pacingRate() Bandwidth {
	rate := b.pacingRateValue
	if rate == 0 {
		rate = bbrScaleBandwidth(bbrBandwidthFromDelta(b.initialCongestionWindow, b.getMinRtt()), defaultHighGain)
	}
	return min(b.maxPacingRate, rate)
}

func (b *bbrSender) OnPacketSent(sentTime monotime.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytesSent protocol.ByteCount, isRetransmittable bool) {
	rate := b.pacingRate()
	b.pacer.SentPacket(sentTime, bytesSent, rate)
	if isRetransmittable && b.mode == bbrModeStartup {
		if b.startupRoundStart.IsZero() {
			b.startupRoundStart = sentTime
		}
		b.startupRoundPacingLimited = b.startupRoundPacingLimited || rate == b.maxPacingRate
	}
	if isRetransmittable && bytesInFlight == 0 {
		b.exitingQuiescence = b.sampler.IsAppLimited()
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

	var isRoundStart bool
	lastAcked := protocol.InvalidPacketNumber
	if len(b.packetsAcked) > 0 {
		lastAcked = b.packetsAcked[len(b.packetsAcked)-1]
		isRoundStart = b.updateRoundTripCounter(lastAcked)
	}
	b.updateRecoveryState(lastAcked, len(b.packetsLost) > 0, isRoundStart)

	sample := b.sampler.OnAcksEnd(
		eventTime,
		b.packetsAcked,
		b.packetsLost,
		b.maxBandwidth.GetBest(),
		b.roundTripCount,
	)
	if sample.lastPacketSendState.isValid {
		b.lastSampleIsAppLimited = sample.lastPacketSendState.isAppLimited
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
	if !b.isAtFullBandwidth {
		b.checkIfPacingLimitReached(eventTime, bytesAcked, isRoundStart)
		if isRoundStart && !b.isAtFullBandwidth {
			b.checkIfFullBandwidthReached(&lastPacketSendState)
		}
	}

	b.maybeExitStartupOrDrain(eventTime)
	b.maybeEnterOrExitProbeRtt(eventTime, isRoundStart, minRttExpired)
	b.calculatePacingRate(eventTime)
	b.calculateCongestionWindow(bytesAcked, excessAcked)
	b.calculateRecoveryWindow(bytesAcked, bytesLost)

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
	b.minCongestionWindow = 4 * size
	b.maxCongestionWindow = protocol.MaxCongestionWindowPackets * size
	b.congestionWindow = max(b.congestionWindow, b.minCongestionWindow)
	b.pacer.SetMaxDatagramSize(size)
	b.updateConnectionStats()
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
		return min(b.congestionWindow, b.recoveryWindow)
	}
	return b.congestionWindow
}

func (b *bbrSender) bandwidthEstimate() Bandwidth {
	return b.maxBandwidth.GetBest()
}

func (b *bbrSender) getMinRtt() time.Duration {
	if b.minRtt != 0 {
		return b.minRtt
	}
	if b.rttStats.HasMeasurement() {
		if minRtt := b.rttStats.MinRTT(); minRtt > 0 {
			return minRtt
		}
	}
	if initialRTT := b.rttStats.SmoothedRTT(); initialRTT > 0 {
		return initialRTT
	}
	return utils.DefaultInitialRTT
}

func (b *bbrSender) getTargetCongestionWindow(gain float64) protocol.ByteCount {
	bdp := bdpFromRttAndBandwidth(b.getMinRtt(), b.bandwidthEstimate())
	congestionWindow := bbrScaleBytes(bdp, gain)
	if congestionWindow == 0 {
		congestionWindow = bbrScaleBytes(b.initialCongestionWindow, gain)
	}
	return max(congestionWindow, b.minCongestionWindow)
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

func (b *bbrSender) enterStartupMode() {
	b.mode = bbrModeStartup
	b.pacingGain = defaultHighGain
	b.congestionWindowGain = derivedHighCWNDGain
	b.startupRoundStart = 0
	b.startupRoundBytesAcked = 0
	b.startupRoundAppLimited = false
	b.startupRoundPacingLimited = false
	b.roundsAtPacingLimit = 0
}

func (b *bbrSender) enterProbeBandwidthMode(now monotime.Time) {
	b.mode = bbrModeProbeBw
	b.congestionWindowGain = derivedHighCWNDGain
	b.cycleCurrentOffset = int(b.rand.Uint32N(uint32(gainCycleLength - 1)))
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

	if b.pacingGain > 1.0 && !hasLosses &&
		priorInFlight < b.getTargetCongestionWindow(b.pacingGain) &&
		bbrScaleBandwidth(b.bandwidthEstimate(), b.pacingGain) < b.maxPacingRate {
		shouldAdvanceGainCycling = false
	}
	if b.pacingGain < 1.0 && b.bytesInFlight() <= b.getTargetCongestionWindow(1) {
		shouldAdvanceGainCycling = true
	}

	if shouldAdvanceGainCycling {
		b.cycleCurrentOffset = (b.cycleCurrentOffset + 1) % gainCycleLength
		b.lastCycleStart = now
		b.pacingGain = PacingGain[b.cycleCurrentOffset]
	}
}

func (b *bbrSender) checkIfFullBandwidthReached(lastPacketSendState *sendTimeState) {
	if !lastPacketSendState.isValid || b.lastSampleIsAppLimited {
		return
	}
	bandwidth := b.bandwidthEstimate()
	if bandwidth == 0 {
		return
	}
	target := bbrScaleBandwidth(b.bandwidthAtLastRound, startupGrowthTarget)
	if bandwidth >= target {
		b.bandwidthAtLastRound = bandwidth
		b.roundsWithoutBandwidthGain = 0
		return
	}
	b.roundsWithoutBandwidthGain++
	if b.roundsWithoutBandwidthGain >= roundTripsWithoutGrowthBeforeExitingStartup ||
		b.shouldExitStartupDueToLoss(lastPacketSendState) {
		b.isAtFullBandwidth = true
	}
}

func (b *bbrSender) checkIfPacingLimitReached(now monotime.Time, bytesAcked protocol.ByteCount, isRoundStart bool) {
	if b.mode != bbrModeStartup || b.startupRoundStart.IsZero() {
		return
	}
	b.startupRoundBytesAcked = bbrAddBytes(b.startupRoundBytesAcked, bytesAcked)
	b.startupRoundAppLimited = b.startupRoundAppLimited || b.lastSampleIsAppLimited
	elapsed := now.Sub(b.startupRoundStart)
	if !isRoundStart || elapsed < b.getMinRtt() {
		return
	}
	if !b.startupRoundAppLimited && b.startupRoundPacingLimited &&
		bbrBandwidthFromDelta(b.startupRoundBytesAcked, elapsed) >= bbrScaleBandwidth(b.maxPacingRate, startupPacingLimitThreshold) {
		b.roundsAtPacingLimit++
	} else {
		b.roundsAtPacingLimit = 0
	}
	if b.roundsAtPacingLimit >= startupRoundsAtPacingLimit {
		b.isAtFullBandwidth = true
	}
	b.startupRoundStart = now
	b.startupRoundBytesAcked = 0
	b.startupRoundAppLimited = false
	b.startupRoundPacingLimited = false
}

func (b *bbrSender) OnApplicationLimited(bytesInFlight protocol.ByteCount) {
	if bytesInFlight < b.GetCongestionWindow() {
		b.sampler.OnAppLimited()
		if b.mode == bbrModeStartup {
			b.startupRoundAppLimited = true
			b.roundsAtPacingLimit = 0
		}
	}
}

func (b *bbrSender) OnPacketNeutered(packetNumber protocol.PacketNumber) {
	b.sampler.OnPacketNeutered(packetNumber)
}

func (b *bbrSender) RemoveObsoletePackets(leastUnacked protocol.PacketNumber) {
	b.sampler.RemoveObsoletePackets(leastUnacked)
}

func (b *bbrSender) maybeExitStartupOrDrain(now monotime.Time) {
	if b.mode == bbrModeStartup && b.isAtFullBandwidth {
		b.mode = bbrModeDrain
		b.pacingGain = 1 / defaultHighGain
		b.congestionWindowGain = derivedHighCWNDGain
	}
	if b.mode == bbrModeDrain && b.bytesInFlight() <= b.getTargetCongestionWindow(1) {
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
					b.enterStartupMode()
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

func (b *bbrSender) calculatePacingRate(now monotime.Time) {
	bandwidth := b.bandwidthEstimate()
	if bandwidth != 0 {
		target := bbrScaleBandwidth(bandwidth, b.pacingGain)
		switch {
		case b.isAtFullBandwidth:
			b.pacingRateValue = target
		case b.pacingRateValue == 0 && b.rttStats.HasMeasurement():
			b.pacingRateValue = bbrBandwidthFromDelta(b.initialCongestionWindow, b.rttStats.MinRTT())
		default:
			b.pacingRateValue = max(b.pacingRateValue, target)
		}
	}
	b.pacer.SetRate(now, b.pacingRate())
}

func (b *bbrSender) calculateCongestionWindow(bytesAcked, excessAcked protocol.ByteCount) {
	if b.mode == bbrModeProbeRtt {
		return
	}

	targetWindow := b.getTargetCongestionWindow(b.congestionWindowGain)
	if b.isAtFullBandwidth {
		targetWindow = bbrAddBytes(targetWindow, b.sampler.MaxAckHeight())
	} else {
		targetWindow = bbrAddBytes(targetWindow, excessAcked)
	}

	if b.isAtFullBandwidth {
		b.congestionWindow = min(targetWindow, b.congestionWindow+bytesAcked)
	} else if b.congestionWindow < targetWindow ||
		b.sampler.TotalBytesAcked() < b.initialCongestionWindow {
		b.congestionWindow += bytesAcked
	}

	b.congestionWindow = max(b.congestionWindow, b.minCongestionWindow)
	b.congestionWindow = min(b.congestionWindow, b.maxCongestionWindow)
}

func (b *bbrSender) calculateRecoveryWindow(bytesAcked, bytesLost protocol.ByteCount) {
	if b.recoveryState == bbrRecoveryStateNotInRecovery {
		return
	}

	if b.recoveryWindow == 0 {
		b.recoveryWindow = b.bytesInFlight() + bytesAcked
		b.recoveryWindow = max(b.recoveryWindow, b.minCongestionWindow)
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

	b.recoveryWindow = max(b.recoveryWindow, b.bytesInFlight()+bytesAcked)
	b.recoveryWindow = max(b.recoveryWindow, b.minCongestionWindow)
}

func (b *bbrSender) shouldExitStartupDueToLoss(lastPacketSendState *sendTimeState) bool {
	if b.numLossEventsInRound < defaultStartupFullLossCount || !lastPacketSendState.isValid {
		return false
	}
	inflightAtSend := lastPacketSendState.bytesInFlight
	if inflightAtSend > 0 && b.bytesLostInRound > 0 {
		return b.bytesLostInRound > protocol.ByteCount(float64(inflightAtSend)*startupLossThreshold)
	}
	return false
}
