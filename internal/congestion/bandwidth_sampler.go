package congestion

import (
	"math"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils/ringbuffer"
)

const (
	infRTT                             = time.Duration(math.MaxInt64)
	defaultConnectionStateMapQueueSize = 512
	defaultCandidatesBufferSize        = 512
)

type roundTripCount uint64

// SendTimeState is a subset of ConnectionStateOnSentPacket which is returned
// to the caller when the packet is acked or lost.
type sendTimeState struct {
	// Whether other states in this object is valid.
	isValid bool
	// Whether the sender is app limited at the time the packet was sent.
	// App limited bandwidth sample might be artificially low because the sender
	// did not have enough data to send in order to saturate the link.
	isAppLimited bool
	// Total number of sent bytes at the time the packet was sent.
	// Includes the packet itself.
	totalBytesSent protocol.ByteCount
	// Total number of acked bytes at the time the packet was sent.
	totalBytesAcked protocol.ByteCount
	// Total number of lost bytes at the time the packet was sent.
	totalBytesLost protocol.ByteCount
	// Total number of inflight bytes at the time the packet was sent.
	// Includes the packet itself.
	// It should be equal to |total_bytes_sent| minus the sum of
	// |total_bytes_acked|, |total_bytes_lost| and total neutered bytes.
	bytesInFlight protocol.ByteCount
}

func newSendTimeState(
	isAppLimited bool,
	totalBytesSent protocol.ByteCount,
	totalBytesAcked protocol.ByteCount,
	totalBytesLost protocol.ByteCount,
	bytesInFlight protocol.ByteCount,
) *sendTimeState {
	return &sendTimeState{
		isValid:         true,
		isAppLimited:    isAppLimited,
		totalBytesSent:  totalBytesSent,
		totalBytesAcked: totalBytesAcked,
		totalBytesLost:  totalBytesLost,
		bytesInFlight:   bytesInFlight,
	}
}

type extraAckedEvent struct {
	// The excess bytes acknowledged in the time delta for this event.
	extraAcked protocol.ByteCount
	// The bytes acknowledged and time delta from the event.
	bytesAcked protocol.ByteCount
	// The time delta over which the excess bytes were acknowledged.
	timeDelta time.Duration
	// The round trip of the event.
	round roundTripCount
}

func maxExtraAckedEventFunc(a, b extraAckedEvent) int {
	if a.extraAcked > b.extraAcked {
		return 1
	} else if a.extraAcked < b.extraAcked {
		return -1
	}
	return 0
}

type bandwidthSample struct {
	// The bandwidth at that particular sample. Zero if no valid bandwidth sample
	// is available.
	bandwidth Bandwidth
	// The RTT measurement at this particular sample. Zero if no RTT sample is
	// available. Does not correct for delayed ack time.
	rtt time.Duration
	// |send_rate| is computed from the current packet being acked('P') and an
	// earlier packet that is acked before P was sent.
	sendRate Bandwidth
	// States captured when the packet was sent.
	stateAtSend sendTimeState
}

func newBandwidthSample() *bandwidthSample {
	return &bandwidthSample{
		sendRate: math.MaxUint64,
	}
}

// MaxAckHeightTracker is part of the BandwidthSampler. It is called after every
// ack event to keep track the degree of ack aggregation(a.k.a "ack height").
type maxAckHeightTracker struct {
	// Tracks the maximum number of bytes acked faster than the estimated
	// bandwidth.
	maxAckHeightFilter *WindowedFilter[extraAckedEvent, roundTripCount]
	// The time this aggregation started and the number of bytes acked during it.
	aggregationEpochStartTime monotime.Time
	aggregationEpochBytes     protocol.ByteCount
	// The last sent packet number before the current aggregation epoch started.
	lastSentPacketNumberBeforeEpoch protocol.PacketNumber
	// The number of ack aggregation epochs ever started, including the ongoing
	// one.
	numAckAggregationEpochs uint64
	// Threshold for detecting ack aggregation, expressed as a multiplier of the
	// estimated bandwidth.
	ackAggregationBandwidthThreshold float64
	// Whether to start a new ack aggregation epoch after a full round trip.
	startNewAggregationEpochAfterFullRound bool
	// Whether to reduce the extra acked bytes when the estimated bandwidth
	// increases.
	reduceExtraAckedOnBandwidthIncrease bool
}

func newMaxAckHeightTracker(windowLength roundTripCount) *maxAckHeightTracker {
	return &maxAckHeightTracker{
		maxAckHeightFilter:               NewWindowedFilter(windowLength, maxExtraAckedEventFunc),
		lastSentPacketNumberBeforeEpoch:  protocol.InvalidPacketNumber,
		ackAggregationBandwidthThreshold: 1.0,
	}
}

func (m *maxAckHeightTracker) Get() protocol.ByteCount {
	return m.maxAckHeightFilter.GetBest().extraAcked
}

func (m *maxAckHeightTracker) Update(
	bandwidthEstimate Bandwidth,
	isNewMaxBandwidth bool,
	roundTripCount roundTripCount,
	lastSentPacketNumber protocol.PacketNumber,
	lastAckedPacketNumber protocol.PacketNumber,
	ackTime monotime.Time,
	bytesAcked protocol.ByteCount,
) protocol.ByteCount {
	forceNewEpoch := false

	if m.reduceExtraAckedOnBandwidthIncrease && isNewMaxBandwidth {
		// Save and clear existing entries.
		best := m.maxAckHeightFilter.GetBest()
		secondBest := m.maxAckHeightFilter.GetSecondBest()
		thirdBest := m.maxAckHeightFilter.GetThirdBest()
		m.maxAckHeightFilter.Clear()

		// Reinsert the heights into the filter after recalculating.
		expectedBytesAcked := bytesFromBandwidthAndTimeDelta(bandwidthEstimate, best.timeDelta)
		if expectedBytesAcked < best.bytesAcked {
			best.extraAcked = best.bytesAcked - expectedBytesAcked
			m.maxAckHeightFilter.Update(best, best.round)
		}
		expectedBytesAcked = bytesFromBandwidthAndTimeDelta(bandwidthEstimate, secondBest.timeDelta)
		if expectedBytesAcked < secondBest.bytesAcked {
			secondBest.extraAcked = secondBest.bytesAcked - expectedBytesAcked
			m.maxAckHeightFilter.Update(secondBest, secondBest.round)
		}
		expectedBytesAcked = bytesFromBandwidthAndTimeDelta(bandwidthEstimate, thirdBest.timeDelta)
		if expectedBytesAcked < thirdBest.bytesAcked {
			thirdBest.extraAcked = thirdBest.bytesAcked - expectedBytesAcked
			m.maxAckHeightFilter.Update(thirdBest, thirdBest.round)
		}
	}

	// If any packet sent after the start of the epoch has been acked, start a new
	// epoch.
	if m.startNewAggregationEpochAfterFullRound &&
		m.lastSentPacketNumberBeforeEpoch != protocol.InvalidPacketNumber &&
		lastAckedPacketNumber != protocol.InvalidPacketNumber &&
		lastAckedPacketNumber > m.lastSentPacketNumberBeforeEpoch {
		forceNewEpoch = true
	}
	if m.aggregationEpochStartTime.IsZero() || forceNewEpoch {
		m.aggregationEpochBytes = bytesAcked
		m.aggregationEpochStartTime = ackTime
		m.lastSentPacketNumberBeforeEpoch = lastSentPacketNumber
		m.numAckAggregationEpochs++
		return 0
	}

	// Compute how many bytes are expected to be delivered, assuming max bandwidth
	// is correct.
	aggregationDelta := ackTime.Sub(m.aggregationEpochStartTime)
	expectedBytesAcked := bytesFromBandwidthAndTimeDelta(bandwidthEstimate, aggregationDelta)
	// Reset the current aggregation epoch as soon as the ack arrival rate is less
	// than or equal to the max bandwidth.
	if m.aggregationEpochBytes <= protocol.ByteCount(m.ackAggregationBandwidthThreshold*float64(expectedBytesAcked)) {
		// Reset to start measuring a new aggregation epoch.
		m.aggregationEpochBytes = bytesAcked
		m.aggregationEpochStartTime = ackTime
		m.lastSentPacketNumberBeforeEpoch = lastSentPacketNumber
		m.numAckAggregationEpochs++
		return 0
	}

	// Accumulate the bytes acknowledged in the current aggregation epoch.
	m.aggregationEpochBytes += bytesAcked

	// Compute how many extra bytes were delivered vs max bandwidth.
	extraBytesAcked := m.aggregationEpochBytes - expectedBytesAcked
	newEvent := extraAckedEvent{
		extraAcked: expectedBytesAcked,
		bytesAcked: m.aggregationEpochBytes,
		timeDelta:  aggregationDelta,
	}
	m.maxAckHeightFilter.Update(newEvent, roundTripCount)
	return extraBytesAcked
}

func (m *maxAckHeightTracker) SetFilterWindowLength(length roundTripCount) {
	m.maxAckHeightFilter.SetWindowLength(length)
}

func (m *maxAckHeightTracker) Reset(newHeight protocol.ByteCount, newTime roundTripCount) {
	newEvent := extraAckedEvent{
		extraAcked: newHeight,
		round:      newTime,
	}
	m.maxAckHeightFilter.Reset(newEvent, newTime)
}

func (m *maxAckHeightTracker) SetAckAggregationBandwidthThreshold(threshold float64) {
	m.ackAggregationBandwidthThreshold = threshold
}

func (m *maxAckHeightTracker) SetStartNewAggregationEpochAfterFullRound(value bool) {
	m.startNewAggregationEpochAfterFullRound = value
}

func (m *maxAckHeightTracker) SetReduceExtraAckedOnBandwidthIncrease(value bool) {
	m.reduceExtraAckedOnBandwidthIncrease = value
}

func (m *maxAckHeightTracker) AckAggregationBandwidthThreshold() float64 {
	return m.ackAggregationBandwidthThreshold
}

func (m *maxAckHeightTracker) NumAckAggregationEpochs() uint64 {
	return m.numAckAggregationEpochs
}

// AckPoint represents a point on the ack line.
type ackPoint struct {
	ackTime         monotime.Time
	totalBytesAcked protocol.ByteCount
}

// RecentAckPoints maintains the most recent 2 ack points at distinct times.
type recentAckPoints struct {
	ackPoints [2]ackPoint
}

func (r *recentAckPoints) Update(ackTime monotime.Time, totalBytesAcked protocol.ByteCount) {
	if ackTime.Before(r.ackPoints[1].ackTime) {
		r.ackPoints[1].ackTime = ackTime
	} else if ackTime.After(r.ackPoints[1].ackTime) {
		r.ackPoints[0] = r.ackPoints[1]
		r.ackPoints[1].ackTime = ackTime
	}

	r.ackPoints[1].totalBytesAcked = totalBytesAcked
}

func (r *recentAckPoints) Clear() {
	r.ackPoints[0] = ackPoint{}
	r.ackPoints[1] = ackPoint{}
}

func (r *recentAckPoints) MostRecentPoint() *ackPoint {
	return &r.ackPoints[1]
}

func (r *recentAckPoints) LessRecentPoint() *ackPoint {
	if r.ackPoints[0].totalBytesAcked != 0 {
		return &r.ackPoints[0]
	}

	return &r.ackPoints[1]
}

// ConnectionStateOnSentPacket represents the information about a sent packet
// and the state of the connection at the moment the packet was sent,
// specifically the information about the most recently acknowledged packet at
// that moment.
type connectionStateOnSentPacket struct {
	// Time at which the packet is sent.
	sentTime monotime.Time
	// Size of the packet.
	size protocol.ByteCount
	// The value of |totalBytesSentAtLastAckedPacket| at the time the
	// packet was sent.
	totalBytesSentAtLastAckedPacket protocol.ByteCount
	// The value of |lastAckedPacketSentTime| at the time the packet was
	// sent.
	lastAckedPacketSentTime monotime.Time
	// The value of |lastAckedPacketAckTime| at the time the packet was
	// sent.
	lastAckedPacketAckTime monotime.Time
	// Send time states that are returned to the congestion controller when the
	// packet is acked or lost.
	sendTimeState sendTimeState
}

// Snapshot constructor. Records the current state of the bandwidth
// sampler.
// |bytes_in_flight| is the bytes in flight right after the packet is sent.
func newConnectionStateOnSentPacket(
	sentTime monotime.Time,
	size protocol.ByteCount,
	bytesInFlight protocol.ByteCount,
	sampler *bandwidthSampler,
) *connectionStateOnSentPacket {
	return &connectionStateOnSentPacket{
		sentTime:                        sentTime,
		size:                            size,
		totalBytesSentAtLastAckedPacket: sampler.totalBytesSentAtLastAckedPacket,
		lastAckedPacketSentTime:         sampler.lastAckedPacketSentTime,
		lastAckedPacketAckTime:          sampler.lastAckedPacketAckTime,
		sendTimeState: *newSendTimeState(
			sampler.isAppLimited,
			sampler.totalBytesSent,
			sampler.totalBytesAcked,
			sampler.totalBytesLost,
			bytesInFlight,
		),
	}
}

// BandwidthSampler keeps track of sent and acknowledged packets and outputs a
// bandwidth sample for every packet acknowledged. The samples are taken for
// individual packets, and are not filtered; the consumer has to filter the
// bandwidth samples itself. In certain cases, the sampler will locally severely
// underestimate the bandwidth, hence a maximum filter with a size of at least
// one RTT is recommended.
//
// This class bases its samples on the slope of two curves: the number of bytes
// sent over time, and the number of bytes acknowledged as received over time.
// It produces a sample of both slopes for every packet that gets acknowledged,
// based on a slope between two points on each of the corresponding curves. Note
// that due to the packet loss, the number of bytes on each curve might get
// further and further away from each other, meaning that it is not feasible to
// compare byte values coming from different curves with each other.
//
// The obvious points for measuring slope sample are the ones corresponding to
// the packet that was just acknowledged. Let us denote them as S_1 (point at
// which the current packet was sent) and A_1 (point at which the current packet
// was acknowledged). However, taking a slope requires two points on each line,
// so estimating bandwidth requires picking a packet in the past with respect to
// which the slope is measured.
//
// For that purpose, BandwidthSampler always keeps track of the most recently
// acknowledged packet, and records it together with every outgoing packet.
// When a packet gets acknowledged (A_1), it has not only information about when
// it itself was sent (S_1), but also the information about the latest
// acknowledged packet right before it was sent (S_0 and A_0).
//
// Based on that data, send and ack rate are estimated as:
//
//	send_rate = (bytes(S_1) - bytes(S_0)) / (time(S_1) - time(S_0))
//	ack_rate = (bytes(A_1) - bytes(A_0)) / (time(A_1) - time(A_0))
//
// Here, the ack rate is intuitively the rate we want to treat as bandwidth.
// However, in certain cases (e.g. ack compression) the ack rate at a point may
// end up higher than the rate at which the data was originally sent, which is
// not indicative of the real bandwidth. Hence, we use the send rate as an upper
// bound, and the sample value is
//
//	rate_sample = min(send_rate, ack_rate)
//
// An important edge case handled by the sampler is tracking the app-limited
// samples. There are multiple meaning of "app-limited" used interchangeably,
// hence it is important to understand and to be able to distinguish between
// them.
//
// Meaning 1: connection state. The connection is said to be app-limited when
// there is no outstanding data to send. This means that certain bandwidth
// samples in the future would not be an accurate indication of the link
// capacity, and it is important to inform consumer about that. Whenever
// connection becomes app-limited, the sampler is notified via OnAppLimited()
// method.
//
// Meaning 2: a phase in the bandwidth sampler. As soon as the bandwidth
// sampler becomes notified about the connection being app-limited, it enters
// app-limited phase. In that phase, all *sent* packets are marked as
// app-limited. Note that the connection itself does not have to be
// app-limited during the app-limited phase, and in fact it will not be
// (otherwise how would it send packets?). The boolean flag below indicates
// whether the sampler is in that phase.
//
// Meaning 3: a flag on the sent packet and on the sample. If a sent packet is
// sent during the app-limited phase, the resulting sample related to the
// packet will be marked as app-limited.
//
// With the terminology issue out of the way, let us consider the question of
// what kind of situation it addresses.
//
// Consider a scenario where we first send packets 1 to 20 at a regular
// bandwidth, and then immediately run out of data. After a few seconds, we send
// packets 21 to 60, and only receive ack for 21 between sending packets 40 and
// 41. In this case, when we sample bandwidth for packets 21 to 40, the S_0/A_0
// we use to compute the slope is going to be packet 20, a few seconds apart
// from the current packet, hence the resulting estimate would be extremely low
// and not indicative of anything. Only at packet 41 the S_0/A_0 will become 21,
// meaning that the bandwidth sample would exclude the quiescence.
//
// Based on the analysis of that scenario, we implement the following rule: once
// OnAppLimited() is called, all sent packets will produce app-limited samples
// up until an ack for a packet that was sent after OnAppLimited() was called.
// Note that while the scenario above is not the only scenario when the
// connection is app-limited, the approach works in other cases too.

type congestionEventSample struct {
	// The maximum bandwidth sample from all acked packets.
	// QuicBandwidth::Zero() if no samples are available.
	sampleMaxBandwidth Bandwidth
	// Whether |sample_max_bandwidth| is from a app-limited sample.
	sampleIsAppLimited bool
	// The minimum rtt sample from all acked packets.
	// QuicTime::Delta::Infinite() if no samples are available.
	sampleRtt time.Duration
	// For each packet p in acked packets, this is the max value of INFLIGHT(p),
	// where INFLIGHT(p) is the number of bytes acked while p is inflight.
	sampleMaxInflight protocol.ByteCount
	// The send state of the largest packet in acked_packets, unless it is
	// empty. If acked_packets is empty, it's the send state of the largest
	// packet in lost_packets.
	lastPacketSendState sendTimeState
	// The number of extra bytes acked from this ack event, compared to what is
	// expected from the flow's bandwidth. Larger value means more ack
	// aggregation.
	extraAcked protocol.ByteCount
}

func newCongestionEventSample() *congestionEventSample {
	return &congestionEventSample{
		sampleRtt: infRTT,
	}
}

type bandwidthSampler struct {
	// The total number of congestion controlled bytes sent during the connection.
	totalBytesSent protocol.ByteCount

	// The total number of congestion controlled bytes which were acknowledged.
	totalBytesAcked protocol.ByteCount

	// The total number of congestion controlled bytes which were lost.
	totalBytesLost protocol.ByteCount

	// The total number of congestion controlled bytes which have been neutered.
	totalBytesNeutered protocol.ByteCount

	// The value of |total_bytes_sent_| at the time the last acknowledged packet
	// was sent. Valid only when |last_acked_packet_sent_time_| is valid.
	totalBytesSentAtLastAckedPacket protocol.ByteCount

	// The time at which the last acknowledged packet was sent. Set to
	// QuicTime::Zero() if no valid timestamp is available.
	lastAckedPacketSentTime monotime.Time

	// The time at which the most recent packet was acknowledged.
	lastAckedPacketAckTime monotime.Time

	// The most recently sent packet.
	lastSentPacket protocol.PacketNumber

	// The most recently acked packet.
	lastAckedPacket protocol.PacketNumber

	// The most recently lost packet.
	lastLostPacket protocol.PacketNumber

	// Indicates whether the bandwidth sampler is currently in an app-limited
	// phase.
	isAppLimited bool

	// The packet that will be acknowledged after this one will cause the sampler
	// to exit the app-limited phase.
	endOfAppLimitedPhase protocol.PacketNumber

	// Record of the connection state at the point where each packet in flight was
	// sent, indexed by the packet number.
	connectionStateMap *packetNumberIndexedQueue[connectionStateOnSentPacket]

	// Stores recent acknowledgment points for bandwidth estimation.
	recentAckPoints recentAckPoints

	// Candidate acknowledgment points used for certain calculations.
	a0Candidates ringbuffer.RingBuffer[ackPoint]

	// Tracks the maximum acknowledgment height observed during the connection.
	maxAckHeightTracker *maxAckHeightTracker

	// The total number of bytes acknowledged since the last acknowledgment event.
	totalBytesAckedAfterLastAckEvent protocol.ByteCount

	// True if connection option 'BSAO' is set.
	overestimateAvoidance bool

	// True if connection option 'BBRB' is set.
	limitMaxAckHeightTrackerBySendRate bool
}

func newBandwidthSampler(maxAckHeightTrackerWindowLength roundTripCount) *bandwidthSampler {
	b := &bandwidthSampler{
		maxAckHeightTracker:  newMaxAckHeightTracker(maxAckHeightTrackerWindowLength),
		connectionStateMap:   newPacketNumberIndexedQueue[connectionStateOnSentPacket](defaultConnectionStateMapQueueSize),
		lastSentPacket:       protocol.InvalidPacketNumber,
		lastAckedPacket:      protocol.InvalidPacketNumber,
		endOfAppLimitedPhase: protocol.InvalidPacketNumber,
	}

	b.a0Candidates.Init(defaultCandidatesBufferSize)

	return b
}

func (b *bandwidthSampler) MaxAckHeight() protocol.ByteCount {
	return b.maxAckHeightTracker.Get()
}

func (b *bandwidthSampler) NumAckAggregationEpochs() uint64 {
	return b.maxAckHeightTracker.NumAckAggregationEpochs()
}

func (b *bandwidthSampler) SetMaxAckHeightTrackerWindowLength(length roundTripCount) {
	b.maxAckHeightTracker.SetFilterWindowLength(length)
}

func (b *bandwidthSampler) ResetMaxAckHeightTracker(newHeight protocol.ByteCount, newTime roundTripCount) {
	b.maxAckHeightTracker.Reset(newHeight, newTime)
}

func (b *bandwidthSampler) SetStartNewAggregationEpochAfterFullRound(value bool) {
	b.maxAckHeightTracker.SetStartNewAggregationEpochAfterFullRound(value)
}

func (b *bandwidthSampler) SetLimitMaxAckHeightTrackerBySendRate(value bool) {
	b.limitMaxAckHeightTrackerBySendRate = value
}

func (b *bandwidthSampler) SetReduceExtraAckedOnBandwidthIncrease(value bool) {
	b.maxAckHeightTracker.SetReduceExtraAckedOnBandwidthIncrease(value)
}

func (b *bandwidthSampler) EnableOverestimateAvoidance() {
	if b.overestimateAvoidance {
		return
	}

	b.overestimateAvoidance = true
	b.maxAckHeightTracker.SetAckAggregationBandwidthThreshold(2.0)
}

func (b *bandwidthSampler) IsOverestimateAvoidanceEnabled() bool {
	return b.overestimateAvoidance
}

func (b *bandwidthSampler) OnPacketSent(
	sentTime monotime.Time,
	bytesInFlight protocol.ByteCount,
	packetNumber protocol.PacketNumber,
	bytesSent protocol.ByteCount,
	isRetransmittable bool,
) {
	b.lastSentPacket = packetNumber

	if !isRetransmittable {
		return
	}

	// Increment the total bytes sent counter with the size of the current packet.
	b.totalBytesSent += bytesSent

	// If there are no packets in flight, the time at which the new transmission
	// opens can be treated as the A_0 point for the purpose of bandwidth
	// sampling. This underestimates bandwidth to some extent, and produces some
	// artificially low samples for most packets in flight, but it provides with
	// samples at important points where we would not have them otherwise, most
	// importantly at the beginning of the connection.
	if bytesInFlight == 0 {
		b.lastAckedPacketAckTime = sentTime
		if b.overestimateAvoidance {
			b.recentAckPoints.Clear()
			b.recentAckPoints.Update(sentTime, b.totalBytesAcked)
			b.a0Candidates.Clear()
			b.a0Candidates.PushBack(*b.recentAckPoints.MostRecentPoint())
		}
		b.totalBytesSentAtLastAckedPacket = b.totalBytesSent
		// In this situation ack compression is not a concern, set send rate to
		// effectively infinite.
		b.lastAckedPacketSentTime = sentTime
	}

	b.connectionStateMap.Emplace(packetNumber, newConnectionStateOnSentPacket(
		sentTime,
		bytesSent,
		bytesInFlight+bytesSent,
		b,
	))
}

func (b *bandwidthSampler) OnAcksEnd(
	eventTime monotime.Time,
	packetsAcked []protocol.PacketNumber,
	packetsLost []protocol.PacketNumber,
	maxBandwidth Bandwidth,
	limitBandwidth Bandwidth,
	roundTripCount roundTripCount,
) congestionEventSample {
	// Process lost packets.
	var lastLostPacketSendState sendTimeState
	for _, pn := range packetsLost {
		sendState := b.onPacketLost(pn)
		if sendState.isValid {
			lastLostPacketSendState = sendState
		}
	}

	eventSample := newCongestionEventSample()

	// Handle loss-only events.
	if len(packetsAcked) == 0 {
		// Only populate send state for a loss-only event.
		eventSample.lastPacketSendState = lastLostPacketSendState
		return *eventSample
	}

	var maxSendRate Bandwidth

	// Process acknowledged packets.
	var lastAckedPacketSendState sendTimeState
	for _, pn := range packetsAcked {
		sample := b.onPacketAcknowledged(eventTime, pn)
		if !sample.stateAtSend.isValid {
			continue
		}

		lastAckedPacketSendState = sample.stateAtSend

		if sample.rtt != 0 {
			eventSample.sampleRtt = Min(eventSample.sampleRtt, sample.rtt)
		}

		if sample.bandwidth > eventSample.sampleMaxBandwidth {
			eventSample.sampleMaxBandwidth = sample.bandwidth
			eventSample.sampleIsAppLimited = sample.stateAtSend.isAppLimited
		}

		if sample.sendRate != math.MaxUint64 {
			maxSendRate = Max(maxSendRate, sample.sendRate)
		}

		inflightSample := b.totalBytesAcked - lastAckedPacketSendState.totalBytesAcked
		if inflightSample > eventSample.sampleMaxInflight {
			eventSample.sampleMaxInflight = inflightSample
		}
	}

	// Determine last packet send state.
	if !lastLostPacketSendState.isValid {
		eventSample.lastPacketSendState = lastAckedPacketSendState
	} else if !lastAckedPacketSendState.isValid {
		eventSample.lastPacketSendState = lastLostPacketSendState
	} else {
		// Handle case where loss detection overlaps with acknowledgment.
		if packetsLost[len(packetsLost)-1] > packetsAcked[len(packetsAcked)-1] {
			eventSample.lastPacketSendState = lastLostPacketSendState
		} else {
			eventSample.lastPacketSendState = lastAckedPacketSendState
		}
	}

	// Update max bandwidth and extra acknowledged bytes.
	maxBandwidth = Max(maxBandwidth, eventSample.sampleMaxBandwidth)
	if b.limitMaxAckHeightTrackerBySendRate {
		maxBandwidth = Max(maxBandwidth, maxSendRate)
	}
	isNewMaxBandwidth := eventSample.sampleMaxBandwidth > maxBandwidth
	eventSample.extraAcked = b.extraAcked(
		Min(maxBandwidth, limitBandwidth),
		isNewMaxBandwidth,
		roundTripCount,
	)

	return *eventSample
}

func (b *bandwidthSampler) onPacketLost(packetNumber protocol.PacketNumber) (s sendTimeState) {
	b.lastLostPacket = packetNumber
	if sentPacketPointer := b.connectionStateMap.GetEntry(packetNumber); sentPacketPointer != nil {
		b.totalBytesLost += sentPacketPointer.size
		sentPacketToSendTimeState(sentPacketPointer, &s)
	}
	return s
}

func (b *bandwidthSampler) OnPacketNeutered(packetNumber protocol.PacketNumber) {
	b.connectionStateMap.Remove(packetNumber, func(sentPacket connectionStateOnSentPacket) {
		b.totalBytesNeutered += sentPacket.size
	})
}

func (b *bandwidthSampler) OnAppLimited() {
	b.isAppLimited = true
	b.endOfAppLimitedPhase = b.lastSentPacket
}

func (b *bandwidthSampler) RemoveObsoletePackets(leastUnacked protocol.PacketNumber) {
	// A packet can become obsolete when it is removed from QuicUnackedPacketMap's
	// view of inflight before it is acked or marked as lost. For example, when
	// QuicSentPacketManager::RetransmitCryptoPackets retransmits a crypto packet,
	// the packet is removed from QuicUnackedPacketMap's inflight, but is not
	// marked as acked or lost in the BandwidthSampler.
	b.connectionStateMap.RemoveUpTo(leastUnacked)
}

func (b *bandwidthSampler) TotalBytesSent() protocol.ByteCount {
	return b.totalBytesSent
}

func (b *bandwidthSampler) TotalBytesLost() protocol.ByteCount {
	return b.totalBytesLost
}

func (b *bandwidthSampler) TotalBytesAcked() protocol.ByteCount {
	return b.totalBytesAcked
}

func (b *bandwidthSampler) TotalBytesNeutered() protocol.ByteCount {
	return b.totalBytesNeutered
}

func (b *bandwidthSampler) IsAppLimited() bool {
	return b.isAppLimited
}

func (b *bandwidthSampler) EndOfAppLimitedPhase() protocol.PacketNumber {
	return b.endOfAppLimitedPhase
}

func (b *bandwidthSampler) chooseA0Point(totalBytesAcked protocol.ByteCount, a0 *ackPoint) bool {
	if b.a0Candidates.Empty() {
		return false
	}

	if b.a0Candidates.Len() == 1 {
		*a0 = *b.a0Candidates.Front()
		return true
	}

	for i := 1; i < b.a0Candidates.Len(); i++ {
		if b.a0Candidates.Offset(i).totalBytesAcked > totalBytesAcked {
			*a0 = *b.a0Candidates.Offset(i - 1)
			if i > 1 {
				for j := 0; j < i-1; j++ {
					b.a0Candidates.PopFront()
				}
			}
			return true
		}
	}

	*a0 = *b.a0Candidates.Back()
	for k := 0; k < b.a0Candidates.Len()-1; k++ {
		b.a0Candidates.PopFront()
	}
	return true
}

func (b *bandwidthSampler) onPacketAcknowledged(eventTime monotime.Time, packetNumber protocol.PacketNumber) bandwidthSample {
	sample := newBandwidthSample()

	// Update the last acknowledged packet number to the current one.
	b.lastAckedPacket = packetNumber

	sentPacketPointer := b.connectionStateMap.GetEntry(packetNumber)
	if sentPacketPointer == nil {
		return *sample
	}

	// OnPacketAcknowledgedInner
	b.totalBytesAcked += sentPacketPointer.size
	b.totalBytesSentAtLastAckedPacket = sentPacketPointer.sendTimeState.totalBytesSent
	b.lastAckedPacketSentTime = sentPacketPointer.sentTime
	b.lastAckedPacketAckTime = eventTime
	if b.overestimateAvoidance {
		b.recentAckPoints.Update(eventTime, b.totalBytesAcked)
	}

	if b.isAppLimited {
		// Exit app-limited phase in two cases:
		// (1) end_of_app_limited_phase_ is not initialized, i.e., so far all
		// packets are sent while there are buffered packets or pending data.
		// (2) The current acked packet is after the sent packet marked as the end
		// of the app limit phase.
		if b.endOfAppLimitedPhase == protocol.InvalidPacketNumber ||
			packetNumber > b.endOfAppLimitedPhase {
			b.isAppLimited = false
		}
	}

	// There might have been no packets acknowledged at the moment when the
	// current packet was sent. In that case, there is no bandwidth sample to
	// make.
	if sentPacketPointer.lastAckedPacketSentTime.IsZero() {
		return *sample
	}

	// Infinite rate indicates that the sampler is supposed to discard the
	// current send rate sample and use only the ack rate.
	sendRate := math.MaxUint64
	if sentPacketPointer.sentTime.After(sentPacketPointer.lastAckedPacketSentTime) {
		sendRate = BandwidthFromDelta(
			sentPacketPointer.sendTimeState.totalBytesSent-sentPacketPointer.totalBytesSentAtLastAckedPacket,
			sentPacketPointer.sentTime.Sub(sentPacketPointer.lastAckedPacketSentTime))
	}

	var a0 ackPoint
	if b.overestimateAvoidance && b.chooseA0Point(sentPacketPointer.sendTimeState.totalBytesAcked, &a0) {
	} else {
		a0.ackTime = sentPacketPointer.lastAckedPacketAckTime
		a0.totalBytesAcked = sentPacketPointer.sendTimeState.totalBytesAcked
	}

	// During the slope calculation, ensure that ack time of the current packet is
	// always larger than the time of the previous packet, otherwise division by
	// zero or integer underflow can occur.
	if eventTime.Sub(a0.ackTime) <= 0 {
		return *sample
	}

	ackRate := BandwidthFromDelta(b.totalBytesAcked-a0.totalBytesAcked, eventTime.Sub(a0.ackTime))

	sample.bandwidth = Min(sendRate, ackRate)
	// Note: this sample does not account for delayed acknowledgement time. This
	// means that the RTT measurements here can be artificially high, especially
	// on low bandwidth connections.
	sample.rtt = eventTime.Sub(sentPacketPointer.sentTime)
	sample.sendRate = sendRate
	sentPacketToSendTimeState(sentPacketPointer, &sample.stateAtSend)

	return *sample
}

func (b *bandwidthSampler) extraAcked(
	bandwidthEstimate Bandwidth,
	isNewMaxBandwidth bool,
	roundTripCount roundTripCount,
) protocol.ByteCount {
	newlyAckedBytes := b.totalBytesAcked - b.totalBytesAckedAfterLastAckEvent
	if newlyAckedBytes == 0 {
		return 0
	}

	b.totalBytesAckedAfterLastAckEvent = b.totalBytesAcked

	extraAcked := b.maxAckHeightTracker.Update(
		bandwidthEstimate,
		isNewMaxBandwidth,
		roundTripCount,
		b.lastSentPacket,
		b.lastAckedPacket,
		b.lastAckedPacketAckTime,
		newlyAckedBytes,
	)

	// If |extra_acked| is zero, i.e. this ack event marks the start of a new ack
	// aggregation epoch, save LessRecentPoint, which is the last ack point of the
	// previous epoch, as a A0 candidate.
	if b.overestimateAvoidance && extraAcked == 0 {
		b.a0Candidates.PushBack(*b.recentAckPoints.LessRecentPoint())
	}

	return extraAcked
}

func sentPacketToSendTimeState(sentPacket *connectionStateOnSentPacket, sendTimeState *sendTimeState) {
	*sendTimeState = sentPacket.sendTimeState
	sendTimeState.isValid = true
}

func bytesFromBandwidthAndTimeDelta(bandwidth Bandwidth, delta time.Duration) protocol.ByteCount {
	return (protocol.ByteCount(bandwidth) * protocol.ByteCount(delta)) /
		(protocol.ByteCount(time.Second) * 8)
}

func timeDeltaFromBytesAndBandwidth(bytes protocol.ByteCount, bandwidth Bandwidth) time.Duration {
	return time.Duration(bytes*8) * time.Second / time.Duration(bandwidth)
}
