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

type sendTimeState struct {
	isValid         bool
	isAppLimited    bool
	totalBytesSent  protocol.ByteCount
	totalBytesAcked protocol.ByteCount
	bytesInFlight   protocol.ByteCount
}

type bandwidthSample struct {
	bandwidth   Bandwidth
	rtt         time.Duration
	stateAtSend sendTimeState
}

type maxAckHeightTracker struct {
	maxAckHeightFilter               *windowedFilter[protocol.ByteCount]
	aggregationEpochStartTime        monotime.Time
	aggregationEpochBytes            protocol.ByteCount
	ackAggregationBandwidthThreshold float64
}

func newMaxAckHeightTracker(length roundTripCount) *maxAckHeightTracker {
	return &maxAckHeightTracker{
		maxAckHeightFilter:               newWindowedFilter[protocol.ByteCount](length),
		ackAggregationBandwidthThreshold: 1,
	}
}

func (m *maxAckHeightTracker) Get() protocol.ByteCount {
	return m.maxAckHeightFilter.GetBest()
}

func (m *maxAckHeightTracker) Update(rate Bandwidth, round roundTripCount, now monotime.Time, bytesAcked protocol.ByteCount) protocol.ByteCount {
	if m.aggregationEpochStartTime.IsZero() {
		m.aggregationEpochBytes = bytesAcked
		m.aggregationEpochStartTime = now
		return 0
	}

	expected := bdpFromRttAndBandwidth(now.Sub(m.aggregationEpochStartTime), rate)
	if m.aggregationEpochBytes <= bbrScaleBytes(expected, m.ackAggregationBandwidthThreshold) {
		m.aggregationEpochBytes = bytesAcked
		m.aggregationEpochStartTime = now
		return 0
	}
	m.aggregationEpochBytes = bbrAddBytes(m.aggregationEpochBytes, bytesAcked)
	extra := m.aggregationEpochBytes - expected
	m.maxAckHeightFilter.Update(extra, round)
	return extra
}

type ackPoint struct {
	ackTime         monotime.Time
	totalBytesAcked protocol.ByteCount
}

type recentAckPoints struct {
	ackPoints [2]ackPoint
}

func (r *recentAckPoints) Update(now monotime.Time, total protocol.ByteCount) {
	if now.Before(r.ackPoints[1].ackTime) {
		r.ackPoints[1].ackTime = now
	} else if now.After(r.ackPoints[1].ackTime) {
		r.ackPoints[0] = r.ackPoints[1]
		r.ackPoints[1].ackTime = now
	}

	r.ackPoints[1].totalBytesAcked = total
}

func (r *recentAckPoints) Clear() {
	*r = recentAckPoints{}
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

type connectionStateOnSentPacket struct {
	sentTime                        monotime.Time
	size                            protocol.ByteCount
	totalBytesSentAtLastAckedPacket protocol.ByteCount
	lastAckedPacketSentTime         monotime.Time
	lastAckedPacketAckTime          monotime.Time
	sendTimeState                   sendTimeState
}

type congestionEventSample struct {
	sampleMaxBandwidth  Bandwidth
	sampleIsAppLimited  bool
	sampleRtt           time.Duration
	lastPacketSendState sendTimeState
	extraAcked          protocol.ByteCount
}

type bandwidthSampler struct {
	totalBytesSent                   protocol.ByteCount
	totalBytesAcked                  protocol.ByteCount
	totalBytesLost                   protocol.ByteCount
	totalBytesSentAtLastAckedPacket  protocol.ByteCount
	lastAckedPacketSentTime          monotime.Time
	lastAckedPacketAckTime           monotime.Time
	lastSentPacket                   protocol.PacketNumber
	isAppLimited                     bool
	endOfAppLimitedPhase             protocol.PacketNumber
	connectionStateMap               *packetNumberIndexedQueue[connectionStateOnSentPacket]
	recentAckPoints                  recentAckPoints
	a0Candidates                     ringbuffer.RingBuffer[ackPoint]
	maxAckHeightTracker              *maxAckHeightTracker
	totalBytesAckedAfterLastAckEvent protocol.ByteCount
	overestimateAvoidance            bool
}

func newBandwidthSampler(length roundTripCount) *bandwidthSampler {
	return &bandwidthSampler{
		maxAckHeightTracker:  newMaxAckHeightTracker(length),
		connectionStateMap:   newPacketNumberIndexedQueue[connectionStateOnSentPacket](defaultConnectionStateMapQueueSize),
		lastSentPacket:       protocol.InvalidPacketNumber,
		endOfAppLimitedPhase: protocol.InvalidPacketNumber,
	}
}

func (b *bandwidthSampler) MaxAckHeight() protocol.ByteCount {
	return b.maxAckHeightTracker.Get()
}

func (b *bandwidthSampler) EnableOverestimateAvoidance() {
	if b.overestimateAvoidance {
		return
	}
	b.overestimateAvoidance = true
	b.a0Candidates.Init(defaultCandidatesBufferSize)
	b.maxAckHeightTracker.ackAggregationBandwidthThreshold = 2
}

func (b *bandwidthSampler) OnPacketSent(now monotime.Time, inflight protocol.ByteCount, pn protocol.PacketNumber, size protocol.ByteCount, retransmittable bool) {
	b.lastSentPacket = pn
	if !retransmittable {
		return
	}
	b.totalBytesSent += size
	if inflight == 0 {
		b.lastAckedPacketAckTime = now
		b.totalBytesSentAtLastAckedPacket = b.totalBytesSent
		b.lastAckedPacketSentTime = now
		if b.overestimateAvoidance {
			b.recentAckPoints.Clear()
			b.recentAckPoints.Update(now, b.totalBytesAcked)
			b.a0Candidates.Clear()
			b.a0Candidates.PushBack(*b.recentAckPoints.MostRecentPoint())
		}
	}
	b.connectionStateMap.Emplace(pn, &connectionStateOnSentPacket{
		sentTime:                        now,
		size:                            size,
		totalBytesSentAtLastAckedPacket: b.totalBytesSentAtLastAckedPacket,
		lastAckedPacketSentTime:         b.lastAckedPacketSentTime,
		lastAckedPacketAckTime:          b.lastAckedPacketAckTime,
		sendTimeState: sendTimeState{
			isValid:         true,
			isAppLimited:    b.isAppLimited,
			totalBytesSent:  b.totalBytesSent,
			totalBytesAcked: b.totalBytesAcked,
			bytesInFlight:   inflight + size,
		},
	})
}

func (b *bandwidthSampler) OnAcksEnd(now monotime.Time, acked, lost []protocol.PacketNumber, maxBandwidth Bandwidth, round roundTripCount) congestionEventSample {
	var lastLost sendTimeState
	for _, pn := range lost {
		if state := b.onPacketLost(pn); state.isValid {
			lastLost = state
		}
	}

	event := congestionEventSample{sampleRtt: infRTT}
	if len(acked) == 0 {
		event.lastPacketSendState = lastLost
		return event
	}
	var lastAcked sendTimeState
	for _, pn := range acked {
		sample := b.onPacketAcknowledged(now, pn)
		if !sample.stateAtSend.isValid {
			continue
		}
		lastAcked = sample.stateAtSend
		if sample.rtt != 0 {
			event.sampleRtt = min(event.sampleRtt, sample.rtt)
		}
		if sample.bandwidth > event.sampleMaxBandwidth {
			event.sampleMaxBandwidth = sample.bandwidth
			event.sampleIsAppLimited = sample.stateAtSend.isAppLimited
		}
	}
	switch {
	case !lastLost.isValid:
		event.lastPacketSendState = lastAcked
	case !lastAcked.isValid:
		event.lastPacketSendState = lastLost
	case lost[len(lost)-1] > acked[len(acked)-1]:
		event.lastPacketSendState = lastLost
	default:
		event.lastPacketSendState = lastAcked
	}
	maxBandwidth = max(maxBandwidth, event.sampleMaxBandwidth)
	event.extraAcked = b.extraAcked(maxBandwidth, round)
	return event
}

func (b *bandwidthSampler) onPacketLost(pn protocol.PacketNumber) (state sendTimeState) {
	if entry := b.connectionStateMap.GetEntry(pn); entry != nil {
		b.totalBytesLost += entry.size
		state = entry.sendTimeState
		b.connectionStateMap.Remove(pn)
	}
	return state
}

func (b *bandwidthSampler) OnPacketNeutered(pn protocol.PacketNumber) {
	b.connectionStateMap.Remove(pn)
}

func (b *bandwidthSampler) OnAppLimited() {
	b.isAppLimited = true
	b.endOfAppLimitedPhase = b.lastSentPacket
}

func (b *bandwidthSampler) RemoveObsoletePackets(leastUnacked protocol.PacketNumber) {
	for !b.connectionStateMap.IsEmpty() {
		pn := b.connectionStateMap.FirstPacket()
		if leastUnacked != protocol.InvalidPacketNumber && pn >= leastUnacked {
			break
		}
		b.OnPacketNeutered(pn)
	}
}

func (b *bandwidthSampler) TotalBytesLost() protocol.ByteCount {
	return b.totalBytesLost
}

func (b *bandwidthSampler) TotalBytesAcked() protocol.ByteCount {
	return b.totalBytesAcked
}

func (b *bandwidthSampler) IsAppLimited() bool {
	return b.isAppLimited
}

func (b *bandwidthSampler) chooseA0Point(total protocol.ByteCount, a0 *ackPoint) bool {
	if b.a0Candidates.Empty() {
		return false
	}
	if b.a0Candidates.Len() == 1 {
		*a0 = b.a0Candidates.PeekFront()
		return true
	}
	for i := 1; i < b.a0Candidates.Len(); i++ {
		if b.a0Candidates.Offset(i).totalBytesAcked > total {
			*a0 = *b.a0Candidates.Offset(i - 1)
			for j := 0; j < i-1; j++ {
				b.a0Candidates.PopFront()
			}
			return true
		}
	}
	*a0 = *b.a0Candidates.Offset(b.a0Candidates.Len() - 1)
	for count := b.a0Candidates.Len() - 1; count > 0; count-- {
		b.a0Candidates.PopFront()
	}
	return true
}

func (b *bandwidthSampler) onPacketAcknowledged(now monotime.Time, pn protocol.PacketNumber) bandwidthSample {
	var sample bandwidthSample
	entry := b.connectionStateMap.GetEntry(pn)
	if entry == nil {
		return sample
	}
	sent := *entry
	b.connectionStateMap.Remove(pn)
	sample.stateAtSend = sent.sendTimeState
	if now.After(sent.sentTime) {
		sample.rtt = now.Sub(sent.sentTime)
	}
	b.totalBytesAcked += sent.size
	b.totalBytesSentAtLastAckedPacket = sent.sendTimeState.totalBytesSent
	b.lastAckedPacketSentTime = sent.sentTime
	b.lastAckedPacketAckTime = now
	if b.overestimateAvoidance {
		b.recentAckPoints.Update(now, b.totalBytesAcked)
	}
	if b.isAppLimited && (b.endOfAppLimitedPhase == protocol.InvalidPacketNumber || pn > b.endOfAppLimitedPhase) {
		b.isAppLimited = false
	}
	if sent.lastAckedPacketSentTime.IsZero() {
		return sample
	}
	sendRate := Bandwidth(math.MaxUint64)
	if sent.sentTime.After(sent.lastAckedPacketSentTime) {
		sendRate = bbrBandwidthFromDelta(sent.sendTimeState.totalBytesSent-sent.totalBytesSentAtLastAckedPacket, sent.sentTime.Sub(sent.lastAckedPacketSentTime))
	}
	var a0 ackPoint
	if !b.overestimateAvoidance || !b.chooseA0Point(sent.sendTimeState.totalBytesAcked, &a0) {
		a0 = ackPoint{ackTime: sent.lastAckedPacketAckTime, totalBytesAcked: sent.sendTimeState.totalBytesAcked}
	}
	if now.Sub(a0.ackTime) <= 0 {
		return sample
	}
	ackRate := bbrBandwidthFromDelta(b.totalBytesAcked-a0.totalBytesAcked, now.Sub(a0.ackTime))
	sample.bandwidth = min(sendRate, ackRate)
	return sample
}

func (b *bandwidthSampler) extraAcked(rate Bandwidth, round roundTripCount) protocol.ByteCount {
	newlyAcked := b.totalBytesAcked - b.totalBytesAckedAfterLastAckEvent
	if newlyAcked == 0 {
		return 0
	}
	b.totalBytesAckedAfterLastAckEvent = b.totalBytesAcked
	extra := b.maxAckHeightTracker.Update(rate, round, b.lastAckedPacketAckTime, newlyAcked)
	if b.overestimateAvoidance && extra == 0 {
		b.a0Candidates.PushBack(*b.recentAckPoints.LessRecentPoint())
	}
	return extra
}
