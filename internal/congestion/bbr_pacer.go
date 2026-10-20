package congestion

import (
	"math"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

type bbrPacer struct {
	budgetAtLastUpdate protocol.ByteCount
	maxDatagramSize    protocol.ByteCount
	lastUpdateTime     monotime.Time
	rate               Bandwidth
}

func newBBRPacer(size protocol.ByteCount) *bbrPacer {
	return &bbrPacer{maxDatagramSize: size}
}

func (p *bbrPacer) SentPacket(now monotime.Time, size protocol.ByteCount, rate Bandwidth) {
	p.SetRate(now, rate)
	p.budgetAtLastUpdate = p.Budget(now, rate) - size
	p.lastUpdateTime = now
}

func (p *bbrPacer) SetRate(now monotime.Time, rate Bandwidth) {
	if p.rate == rate {
		return
	}
	if !p.lastUpdateTime.IsZero() {
		p.budgetAtLastUpdate = min(p.Budget(now, p.rate), p.maxBurstSize(rate))
		p.lastUpdateTime = max(now, p.lastUpdateTime)
	}
	p.rate = rate
}

func (p *bbrPacer) Budget(now monotime.Time, rate Bandwidth) protocol.ByteCount {
	burst := p.maxBurstSize(rate)
	if p.lastUpdateTime.IsZero() {
		return burst
	}
	delta := now.Sub(p.lastUpdateTime)
	if delta <= 0 {
		return p.budgetAtLastUpdate
	}
	added := bdpFromRttAndBandwidth(delta, rate)
	return min(burst, p.budgetAtLastUpdate+added)
}

func (p *bbrPacer) maxBurstSize(rate Bandwidth) protocol.ByteCount {
	return max(10*p.maxDatagramSize, bdpFromRttAndBandwidth(time.Millisecond+protocol.TimerGranularity, rate))
}

func (p *bbrPacer) TimeUntilSend(rate Bandwidth) monotime.Time {
	if p.lastUpdateTime.IsZero() || p.budgetAtLastUpdate >= p.maxDatagramSize {
		return 0
	}
	needed := uint64(p.maxDatagramSize - p.budgetAtLastUpdate)
	delay := bbrMulDivCeil(needed, 8*uint64(time.Second), uint64(rate))
	room := uint64(math.MaxInt64 - int64(p.lastUpdateTime))
	delay = min(room, max(uint64(time.Millisecond), delay))
	return p.lastUpdateTime.Add(time.Duration(delay))
}

func (p *bbrPacer) SetMaxDatagramSize(size protocol.ByteCount) {
	p.maxDatagramSize = size
}
