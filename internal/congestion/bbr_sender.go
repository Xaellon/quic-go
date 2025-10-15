package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

// BbrSender implements BBR congestion control algorithm. BBR aims to estimate
// the current available Bottleneck Bandwidth and RTT (hence the name), and
// regulates the pacing rate and the size of the congestion window based on
// those signals.
//
// BBR relies on pacing in order to function properly. Do not use BBR when
// pacing is disabled.
//

const (
	// Constants based on TCP defaults.
	// The minimum CWND to ensure delayed acks don't reduce bandwidth measurements.
	// Does not inflate the pacing rate.
	defaultMinimumCongestionWindow = protocol.ByteCount(protocol.InitialPacketSize << 2)

	// The gain used for the STARTUP, equal to 2/ln(2).
	defaultHighGain = 2.885

	// The newly derived CWND gain for STARTUP, 2.
	derivedHighCWNDGain = 2.0

	// The default RTT used before an RTT sample is taken.
	defaultInitialRTT = 100 * time.Millisecond
)

// The cycle of gains used during the PROBE_BW stage.
var PacingGain = [...]float64{1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}

const (
	// The length of the gain cycle.
	gainCycleLength = len(PacingGain)
	// The size of the bandwidth filter window, in round-trips.
	bandwidthWindowSize = gainCycleLength + 2

	// The time after which the current min_rtt value expires.
	minRttExpiry = 10 * time.Second
	// The minimum time the connection can spend in PROBE_RTT mode.
	probeRttTime = 200 * time.Millisecond
	// If the bandwidth does not increase by the factor of |kStartupGrowthTarget|
	// within |kRoundTripsWithoutGrowthBeforeExitingStartup| rounds, the connection
	// will exit the STARTUP mode.
	startupGrowthTarget = 1.25
	// Defines the number of consecutive round trips during which the measured
	// bandwidth must not grow significantly for the connection to exit the STARTUP phase.
	// This ensures the connection transitions to the next phase only after reaching
	// a stable bandwidth estimate.
	roundTripsWithoutGrowthBeforeExitingStartup = int64(6)

	// Specifies the maximum number of loss events allowed during the STARTUP phase.
	// Exceeding this limit forces the connection to transition to a more stable phase
	// (e.g., DRAIN or PROBE_BW), ensuring that excessive packet loss is treated
	// as a signal to stop aggressive bandwidth probing.
	defaultStartupFullLossCount = 8
	// Defines the maximum acceptable loss rate during a round trip.
	// If the loss exceeds this threshold, it is treated as a signal of congestion.
	quicBbr2DefaultLossThreshold = 0.05

	// Defines the maximum number of packets that can be sent in a single burst
	// when the pacing timer allows immediate transmission.
	// This limits the potential for short-term queuing and ensures smoother pacing.
	maxBbrBurstPackets = 3
)

type bbrMode int

const (
	// Startup phase of the connection.
	bbrModeStartup = iota
	// After achieving the highest possible bandwidth during the startup, lower
	// the pacing rate in order to drain the queue.
	bbrModeDrain
	// Cruising mode.
	bbrModeProbeBw
	// Temporarily slow down sending in order to empty the buffer and measure
	// the real minimum RTT.
	bbrModeProbeRtt
)

// Indicates how the congestion control limits the amount of bytes in flight.
type bbrRecoveryState int

const (
	// Not in recovery mode; no restrictions on the congestion window.
	bbrRecoveryStateNotInRecovery = iota
	// Allow an extra outstanding byte for each byte acknowledged.
	bbrRecoveryStateConservation
	// Allow two extra outstanding bytes for each byte acknowledged (slow
	// start).
	bbrRecoveryStateGrowth
)

type bbrSender struct {
	rttStats *utils.RTTStats
	clock    Clock
	rand     utils.Rand
	pacer    *pacer

	// Current operational mode of the BBR congestion control algorithm.
	mode bbrMode

	// Bandwidth sampler provides BBR with the bandwidth measurements at
	// individual points.
	sampler *bandwidthSampler

	// The number of the round trips that have occurred during the connection.
	roundTripCount roundTripCount

	// Acknowledgement of any packet after |current_round_trip_end_| will cause
	// the round trip counter to advance.
	currentRoundTripEnd protocol.PacketNumber

	// Number of congestion events with some losses, in the current round.
	numLossEventsInRound uint64

	// Number of total bytes lost in the current round.
	bytesLostInRound protocol.ByteCount

	// The filter that tracks the maximum bandwidth over the multiple recent
	// round-trips.
	maxBandwidth *WindowedFilter[Bandwidth, roundTripCount]

	// Minimum RTT estimate. Automatically expires within 10 seconds (and
	// triggers PROBE_RTT mode) if no new value is sampled during that period.
	minRtt time.Duration
	// The time at which the current value of |min_rtt_| was assigned.
	minRttTimestamp monotime.Time

	// The maximum allowed number of bytes in flight.
	congestionWindow protocol.ByteCount
	// The initial value of the |congestion_window_|.
	initialCongestionWindow protocol.ByteCount
	// The largest value the |congestion_window_| can achieve.
	maxCongestionWindow protocol.ByteCount
	// The smallest value the |congestion_window_| can achieve.
	minCongestionWindow protocol.ByteCount

	// The initial value of the estimate bandwidth.
	initialEstimateBandwidth Bandwidth

	// The pacing gain applied during the STARTUP phase.
	highGain float64

	// The CWND gain applied during the STARTUP phase.
	highCwndGain float64

	// The pacing gain applied during the DRAIN phase.
	drainGain float64

	// The gain currently applied to the pacing rate.
	pacingGain float64

	// The gain currently applied to the congestion window.
	congestionWindowGain float64

	// The gain used for the congestion window during PROBE_BW. Latched from
	// quic_bbr_cwnd_gain flag.
	congestionWindowGainConstant float64

	// The number of RTTs to stay in STARTUP mode.
	numStartupRtts int64

	// Number of round-trips in PROBE_BW mode, used for determining the current
	// pacing gain cycle.
	cycleCurrentOffset int
	// The time at which the last pacing gain cycle was started.
	lastCycleStart monotime.Time

	// Indicates whether the connection has reached the full bandwidth mode.
	isAtFullBandwidth bool
	// Number of rounds during which there was no significant bandwidth increase.
	roundsWithoutBandwidthGain int64
	// The bandwidth compared to which the increase is measured.
	bandwidthAtLastRound Bandwidth

	// Set to true upon exiting quiescence.
	exitingQuiescence bool

	// Time at which PROBE_RTT has to be exited. Setting it to zero indicates
	// that the time is yet unknown as the number of packets in flight has not
	// reached the required value.
	exitProbeRttAt monotime.Time
	// Indicates whether a round-trip has passed since PROBE_RTT became active.
	probeRttRoundPassed bool

	// Indicates whether the most recent bandwidth sample was marked as
	// app-limited.
	lastSampleIsAppLimited bool

	// Current state of recovery.
	recoveryState bbrRecoveryState
	// Receiving acknowledgement of a packet after |end_recovery_at_| will cause
	// BBR to exit the recovery mode. A value above zero indicates at least one
	// loss has been detected, so it must not be set back to zero.
	endRecoveryAt protocol.PacketNumber
	// A window used to limit the number of bytes in flight during loss recovery.
	recoveryWindow protocol.ByteCount

	// When true, add the most recent ack aggregation measurement during STARTUP.
	enableAckAggregationDuringStartup bool
	// When true, expire the windowed ack aggregation values in STARTUP when
	// bandwidth increases more than 25%.
	expireAckAggregationInStartup bool

	// If true, will not exit low gain mode until bytes_in_flight drops below BDP
	// or it's time for high gain mode.
	drainToTarget bool

	// Maximum size of a single datagram that can be sent.
	maxDatagramSize protocol.ByteCount

	// MaxPacingRate is the maximum rate at which packets are sent, in bits per second (bps).
	// It is used to limit the bandwidth used by a connection.
	// This value must be set and cannot be zero.
	// Values higher than the available network bandwidth may lead to unexpected results.
	maxPacingRate Bandwidth

	// Information about recently acknowledged and lost packets for congestion
	// control calculations.
	packetsAcked []protocol.PacketNumber
	packetsLost  []protocol.PacketNumber

	// Current number of bytes in flight to reflect the latest state of the network.
	bytesInFlight func() protocol.ByteCount
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
) *bbrSender {
	b := &bbrSender{
		rttStats:                          rttStats,
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
	b.pacer = newPacer(func() Bandwidth {
		bandwidth := Bandwidth(float64(b.bandwidthEstimate()) * b.congestionWindowGain)
		return Min(bandwidth, b.maxPacingRate)
	})

	// Switch to startup mode to probe for bandwidth.
	b.enterStartupMode(b.clock.Now())

	// Set a high congestion window gain for aggressive bandwidth usage.
	b.setHighCwndGain(derivedHighCWNDGain)

	return b
}

func (b *bbrSender) TimeUntilSend(bytesInFlight protocol.ByteCount) monotime.Time {
	return b.pacer.TimeUntilSend()
}

func (b *bbrSender) HasPacingBudget(now monotime.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *bbrSender) OnPacketSent(sentTime monotime.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytesSent protocol.ByteCount, isRetransmittable bool) {
	// Notify the pacer about the sent packet.
	b.pacer.SentPacket(sentTime, bytesSent)

	// Handle quiescence state.
	if bytesInFlight == 0 {
		b.exitingQuiescence = true
	}

	// Notify the sampler about the sent packet.
	b.sampler.OnPacketSent(sentTime, bytesInFlight, packetNumber, bytesSent, isRetransmittable)
}

func (b *bbrSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

func (b *bbrSender) MaybeExitSlowStart() {
	// not implemented
}

func (b *bbrSender) OnPacketAcked(packetNumber protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time) {
	b.packetsAcked = append(b.packetsAcked, packetNumber)
}

func (b *bbrSender) OnAcksEnd(priorInFlight protocol.ByteCount, eventTime monotime.Time) {
	if len(b.packetsAcked) == 0 && len(b.packetsLost) == 0 {
		return
	}

	totalBytesAckedBefore := b.sampler.TotalBytesAcked()
	totalBytesLostBefore := b.sampler.TotalBytesLost()

	// Checks if the sender is application-limited based on prior in-flight
	// bytes and updates the sampler.
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

	sample := b.sampler.OnAcksEnd(eventTime,
		b.packetsAcked, b.packetsLost, b.maxBandwidth.GetBest(), b.maxPacingRate, b.roundTripCount)
	if sample.lastPacketSendState.isValid {
		b.lastSampleIsAppLimited = sample.lastPacketSendState.isAppLimited
		if sample.sampleMaxBandwidth >= b.maxPacingRate {
			b.lastSampleIsAppLimited = false
		}
	}

	// Avoid updating |max_bandwidth_| if a) this is a loss-only event, or b) all
	// packets in |acked_packets| did not generate valid samples. (e.g. ack of
	// ack-only packets). In both cases, sampler_.total_bytes_acked() will not
	// change.
	if totalBytesAckedBefore != b.sampler.TotalBytesAcked() {
		if !sample.sampleIsAppLimited || sample.sampleMaxBandwidth > b.maxBandwidth.GetBest() {
			b.maxBandwidth.Update(sample.sampleMaxBandwidth, b.roundTripCount)
		}
	}

	var minRttExpired bool
	if sample.sampleRtt != infRTT {
		minRttExpired = b.maybeUpdateMinRtt(eventTime, sample.sampleRtt)
	}

	// Calculate number of packets acked and lost.
	bytesAcked := b.sampler.TotalBytesAcked() - totalBytesAckedBefore
	bytesLost := b.sampler.TotalBytesLost() - totalBytesLostBefore

	// The number of extra bytes acked from this ack event, compared to what is
	// expected from the flow's bandwidth. Larger value means more ack
	// aggregation.
	excessAcked := sample.extraAcked

	// The send state of the largest packet in acked_packets, unless it is
	// empty. If acked_packets is empty, it's the send state of the largest
	// packet in lost_packets.
	lastPacketSendState := sample.lastPacketSendState

	if len(b.packetsLost) > 0 {
		// Number of congestion events with some losses, in the current round.
		b.numLossEventsInRound++
		// Number of total bytes lost in the current round.
		b.bytesLostInRound += bytesLost
	}

	// Handle logic specific to PROBE_BW mode.
	if b.mode == bbrModeProbeBw {
		b.updateGainCyclePhase(eventTime, priorInFlight, len(b.packetsLost) > 0)
	}

	// Handle logic specific to STARTUP and DRAIN modes.
	if isRoundStart && !b.isAtFullBandwidth {
		b.checkIfFullBandwidthReached(&lastPacketSendState)
	}

	b.maybeExitStartupOrDrain(eventTime)

	// Handle logic specific to PROBE_RTT.
	b.maybeEnterOrExitProbeRtt(eventTime, isRoundStart, minRttExpired)

	// After the model is updated, recalculate the congestion
	// window.
	b.calculateCongestionWindow(bytesAcked, excessAcked)
	b.calculateRecoveryWindow(bytesAcked, bytesLost)

	// Cleanup internal state.
	if len(b.packetsLost) > 0 {
		b.sampler.RemoveObsoletePackets(
			b.packetsLost[len(b.packetsLost)-1],
		)
	}
	if len(b.packetsAcked) > 0 {
		bias := protocol.PacketNumber(b.calculateUselessAckBias())
		if uselessPacketNum := b.packetsAcked[0] - bias; uselessPacketNum > 0 {
			b.sampler.RemoveObsoletePackets(uselessPacketNum)
		}
	}
	if isRoundStart {
		// Number of congestion events with some losses, in the current round.
		b.numLossEventsInRound = 0
		// Number of total bytes lost in the current round.
		b.bytesLostInRound = 0
	}

	b.packetsAcked = b.packetsAcked[:0]
	b.packetsLost = b.packetsLost[:0]
}

func (b *bbrSender) OnCongestionEvent(packetNumber protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
	if lostBytes > 0 {
		b.packetsLost = append(b.packetsLost, packetNumber)
	}
}

func (b *bbrSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	// not implemented
}

func (b *bbrSender) SetMaxDatagramSize(size protocol.ByteCount) {
	// Ignore if the new size is smaller than the current maximum datagram size.
	if size < b.maxDatagramSize {
		return
	}

	// Update the maximum datagram size.
	b.maxDatagramSize = size

	// Notify the pacer about the new datagram size.
	b.pacer.SetMaxDatagramSize(size)
}

func (b *bbrSender) InSlowStart() bool {
	return b.mode == bbrModeStartup
}

func (b *bbrSender) InRecovery() bool {
	return b.recoveryState != bbrRecoveryStateNotInRecovery
}

func (b *bbrSender) GetCongestionWindow() protocol.ByteCount {
	// If in ProbeRtt mode, use the ProbeRtt-specific congestion window.
	if b.mode == bbrModeProbeRtt {
		return b.probeRttCongestionWindow()
	}

	// If in recovery mode with a valid recovery window, limit to the smaller of
	// the congestion window and recovery window.
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
		// If we haven't measured an rtt, the bandwidth estimate is unknown.
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

	// min_rtt could be available if the handshake packet gets neutered then
	// gets acknowledged. This could only happen for QUIC crypto where we do not
	// drop keys.
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
		// Minimum RTT expires automatically after 10 seconds.
		b.minRtt = sampleMinRtt
		// The time at which the current value was assigned.
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

	// Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
	// excluded because in that case increased gain and decreased gain would not
	// follow each other.
	b.cycleCurrentOffset = int(b.rand.Int31n(protocol.PacketsPerConnectionID)) % (gainCycleLength - 1)
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
	// In most cases, the cycle is advanced after an RTT passes.
	shouldAdvanceGainCycling := now.After(b.lastCycleStart.Add(b.getMinRtt()))

	// If the pacing gain is above 1.0, the connection is trying to probe the
	// bandwidth by increasing the number of bytes in flight to at least
	// pacing_gain * BDP. Make sure that it actually reaches the target, as long
	// as there are no losses suggesting that the buffers are not able to hold
	// that much.
	if b.pacingGain > 1.0 && !hasLosses && priorInFlight < b.getTargetCongestionWindow(b.pacingGain) {
		shouldAdvanceGainCycling = false
	}

	// If pacing gain is below 1.0, the connection is trying to drain the extra
	// queue which could have been incurred by probing prior to it. If the number
	// of bytes in flight falls down to the estimated BDP value earlier, conclude
	// that the queue has been successfully drained and exit this cycle early.
	if b.pacingGain < 1.0 && b.bytesInFlight() <= b.getTargetCongestionWindow(1) {
		shouldAdvanceGainCycling = true
	}

	if shouldAdvanceGainCycling {
		b.cycleCurrentOffset = (b.cycleCurrentOffset + 1) % gainCycleLength
		b.lastCycleStart = now

		// Stay in low gain mode until the target BDP is hit.
		// Low gain mode will be exited immediately when the target BDP is achieved.
		if b.drainToTarget && b.pacingGain < 1 &&
			PacingGain[b.cycleCurrentOffset] == 1 &&
			b.bytesInFlight() > b.getTargetCongestionWindow(1) {
			return
		}

		b.pacingGain = PacingGain[b.cycleCurrentOffset]
	}
}

func (b *bbrSender) checkIfFullBandwidthReached(lastPacketSendState *sendTimeState) {
	// Exit if the last sample was application-limited.
	if b.lastSampleIsAppLimited {
		return
	}

	// Check if the bandwidth has reached the target growth.
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

	// Increment the counter for rounds without bandwidth gain.
	b.roundsWithoutBandwidthGain++

	// Check if the startup phase should end.
	if b.roundsWithoutBandwidthGain >= b.numStartupRtts ||
		b.shouldExitStartupDueToLoss(lastPacketSendState) {
		b.isAtFullBandwidth = true
	}
}

func (b *bbrSender) maybeAppLimited(bytesInFlight protocol.ByteCount) {
	// Get the current congestion window size.
	congestionWindow := b.GetCongestionWindow()
	if bytesInFlight >= congestionWindow {
		return
	}

	// Determine if the connection is drain-limited.
	drainLimited := b.mode == bbrModeDrain && bytesInFlight > congestionWindow/2
	availableBytes := congestionWindow - bytesInFlight
	// Mark as application-limited if conditions are met.
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
		b.enterProbeBandwidthMode(now)
	}
}

func (b *bbrSender) maybeEnterOrExitProbeRtt(now monotime.Time, isRoundStart, minRttExpired bool) {
	// Check if conditions to enter PROBE_RTT mode are met.
	if minRttExpired && !b.exitingQuiescence && b.mode != bbrModeProbeRtt {
		b.mode = bbrModeProbeRtt
		b.pacingGain = 1.0

		// Do not decide on the time to exit PROBE_RTT until |bytes_in_flight|
		// reaches the target small value.
		b.exitProbeRttAt = monotime.Time(0)
	}

	if b.mode == bbrModeProbeRtt {
		// Mark the sender as application-limited during PROBE_RTT.
		b.sampler.OnAppLimited()

		if b.exitProbeRttAt.IsZero() {
			// If the window is appropriately small, schedule exiting PROBE_RTT.
			// The CWND during PROBE_RTT is kMinimumCongestionWindow, but we allow
			// an extra packet since QUIC checks CWND before sending a packet.
			if b.bytesInFlight() < b.probeRttCongestionWindow()+protocol.MaxPacketBufferSize {
				b.exitProbeRttAt = now.Add(probeRttTime)
				b.probeRttRoundPassed = false
			}
		} else {
			// Check if a round has passed during PROBE_RTT.
			if isRoundStart {
				b.probeRttRoundPassed = true
			}

			// Exit PROBE_RTT mode if conditions are met.
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
	// Disable recovery in startup, if loss-based exit is enabled.
	if !b.isAtFullBandwidth {
		return
	}

	// Exit recovery when there are no losses for a round.
	if hasLosses {
		b.endRecoveryAt = b.sampler.lastSentPacket
	}

	switch b.recoveryState {
	case bbrRecoveryStateNotInRecovery:
		if hasLosses {
			b.recoveryState = bbrRecoveryStateConservation
			// This will cause the |recovery_window_| to be set to the correct
			// value in CalculateRecoveryWindow().
			b.recoveryWindow = 0
			// Since the conservation phase is meant to last for a whole round,
			// extend the current round as if it were started right now.
			b.currentRoundTripEnd = b.sampler.lastSentPacket
		}
	case bbrRecoveryStateConservation:
		if isRoundStart {
			b.recoveryState = bbrRecoveryStateGrowth
		}
		fallthrough
	case bbrRecoveryStateGrowth:
		// Exit recovery if appropriate.
		if !hasLosses && lastAckedPacket > b.endRecoveryAt {
			b.recoveryState = bbrRecoveryStateNotInRecovery
		}
	}
}

func (b *bbrSender) calculateCongestionWindow(bytesAcked, excessAcked protocol.ByteCount) {
	// If in ProbeRTT mode, do not adjust the congestion window.
	if b.mode == bbrModeProbeRtt {
		return
	}

	// Calculate the target congestion window based on the current gain.
	targetWindow := b.getTargetCongestionWindow(b.congestionWindowGain)

	if b.isAtFullBandwidth {
		// Add the max recently measured ack aggregation to the target window.
		targetWindow += b.sampler.MaxAckHeight()
	} else if b.enableAckAggregationDuringStartup {
		// In STARTUP, add the most recent excess acked to create a localized max filter.
		targetWindow += excessAcked
	}

	// Gradually grow the congestion window towards the target window.
	if b.isAtFullBandwidth {
		b.congestionWindow = Min(targetWindow, b.congestionWindow+bytesAcked)
	} else if b.congestionWindow < targetWindow ||
		b.sampler.TotalBytesAcked() < b.initialCongestionWindow {
		// Do not decrease the congestion window in STARTUP phase.
		b.congestionWindow += bytesAcked
	}

	// Enforce the minimum and maximum limits on the congestion window.
	b.congestionWindow = Max(b.congestionWindow, b.minCongestionWindow)
	b.congestionWindow = Min(b.congestionWindow, b.maxCongestionWindow)
}

func (b *bbrSender) calculateRecoveryWindow(bytesAcked, bytesLost protocol.ByteCount) {
	if b.recoveryState == bbrRecoveryStateNotInRecovery {
		return
	}

	// Set up the initial recovery window.
	if b.recoveryWindow == 0 {
		b.recoveryWindow = b.bytesInFlight() + bytesAcked
		b.recoveryWindow = Max(b.recoveryWindow, b.minCongestionWindow)
		return
	}

	// Remove losses from the recovery window, while accounting for a potential
	// integer underflow.
	if b.recoveryWindow >= bytesLost {
		b.recoveryWindow -= bytesLost
	} else {
		b.recoveryWindow = b.maxDatagramSize
	}

	// In CONSERVATION mode, just subtracting losses is sufficient.
	// In GROWTH mode, release additional |bytes_acked| to achieve a slow-start-like behavior.
	if b.recoveryState == bbrRecoveryStateGrowth {
		b.recoveryWindow += bytesAcked
	}

	// Always allow sending at least |bytes_acked| in response.
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
