package congestion

import (
	"math"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

func newTestBBR(rate Bandwidth) (*bbrSender, *protocol.ByteCount) {
	inflight := new(protocol.ByteCount)
	return NewBbrSender(utils.NewRTTStats(), 1280, rate, func() protocol.ByteCount { return *inflight }, nil), inflight
}

func TestBBRSamplingAndReordering(t *testing.T) {
	b, inflight := newTestBBR(1000)
	now := monotime.Now()
	b.OnPacketSent(now, 0, 1, 1280, true)
	b.OnPacketSent(now.Add(time.Millisecond), 1280, 2, 1280, true)
	if got := b.sampler.connectionStateMap.GetEntry(1).sendTimeState.bytesInFlight; got != 1280 {
		t.Fatalf("inflight=%d", got)
	}
	for i, pn := range []protocol.PacketNumber{2, 1} {
		*inflight = protocol.ByteCount(1-i) * 1280
		at := now.Add(time.Duration(100+i) * time.Millisecond)
		b.OnPacketAcked(pn, 1280, *inflight+1280, at)
		b.OnAcksEnd(*inflight+1280, at)
	}
	if b.sampler.TotalBytesAcked() != 2560 || !b.sampler.connectionStateMap.IsEmpty() || b.minRtt == 0 {
		t.Fatal("invalid ACK accounting, cleanup or RTT sample")
	}
	if b.sampler.IsAppLimited() {
		t.Fatal("ACK processing marked the application limited")
	}
}

func TestBBRApplicationLimitedAndIdle(t *testing.T) {
	b, _ := newTestBBR(1_000_000)
	b.OnApplicationLimited(0)
	b.OnPacketSent(monotime.Now(), 0, 1, 1280, true)
	if !b.sampler.IsAppLimited() || !b.exitingQuiescence {
		t.Fatal("missing application-limit or idle-exit state")
	}
}

func TestBBRStartupUsesSamples(t *testing.T) {
	b, _ := newTestBBR(100_000_000)
	state := sendTimeState{isValid: true}
	b.checkIfFullBandwidthReached(&state)
	if b.bandwidthAtLastRound != 0 || b.pacingRate() != 9_453_568 {
		t.Fatal("incorrect bandwidth initialization")
	}
	for round := roundTripCount(1); round <= 6; round++ {
		b.maxBandwidth.Update(1_000_000<<(round-1), round)
		b.checkIfFullBandwidthReached(&state)
	}
	if b.isAtFullBandwidth {
		t.Fatal("STARTUP exited during bandwidth growth")
	}
	for round := roundTripCount(7); round <= 9; round++ {
		b.maxBandwidth.Update(32_000_000, round)
		b.checkIfFullBandwidthReached(&state)
		if round < 9 && b.isAtFullBandwidth {
			t.Fatal("STARTUP exited before three plateau rounds")
		}
	}
	if !b.isAtFullBandwidth {
		t.Fatal("STARTUP did not exit after a plateau")
	}
}

func TestBBRLossOnlyRecovery(t *testing.T) {
	b, inflight := newTestBBR(10_000_000)
	b.isAtFullBandwidth = true
	b.mode = bbrModeProbeBw
	now := monotime.Now()
	b.OnPacketSent(now, 0, 1, 1280, true)
	b.OnCongestionEvent(1, 1280, 1280)
	*inflight = 0
	b.OnAcksEnd(1280, now.Add(100*time.Millisecond))
	if !b.InRecovery() || b.sampler.TotalBytesLost() != 1280 || !b.sampler.connectionStateMap.IsEmpty() {
		t.Fatal("loss-only event was not fully processed")
	}
}

func TestBBRPacingCap(t *testing.T) {
	for _, cap := range []Bandwidth{1, 7, 8, 23, 1000, 100_000_000, math.MaxUint64} {
		b, _ := newTestBBR(cap)
		b.maxBandwidth.Update(cap, 1)
		b.isAtFullBandwidth = true
		for _, gain := range []float64{1 / defaultHighGain, 0.75, 1, 1.25, defaultHighGain} {
			b.pacingGain = gain
			b.calculatePacingRate(monotime.Now())
			if got := b.pacingRate(); got == 0 || got > cap {
				t.Fatalf("cap=%d, gain=%f, rate=%d", cap, gain, got)
			}
		}
	}
}

func TestBBRPacerLowRates(t *testing.T) {
	for _, rate := range []Bandwidth{1, 7, 8, 23, 1000} {
		p := newBBRPacer(1280)
		now := monotime.Now()
		for range 10 {
			p.SentPacket(now, 1280, rate)
		}
		next := p.TimeUntilSend(rate)
		if !next.After(now) || p.Budget(next, rate) < 1280 || p.Budget(next.Add(-time.Nanosecond), rate) >= 1280 {
			t.Fatalf("incorrect pacing deadline for %d bps", rate)
		}
	}
	p := newBBRPacer(1280)
	p.SentPacket(monotime.Now(), 12800, 0)
	if p.TimeUntilSend(0) != monotime.Time(math.MaxInt64) {
		t.Fatal("zero rate did not block safely")
	}
}

func TestBBRWideArithmetic(t *testing.T) {
	cases := [][3]uint64{{100_000_000_000, 100_000_000, 8_000_000_000}, {math.MaxUint64, math.MaxUint64, 1}, {math.MaxUint64, 8_000_000_000, math.MaxInt64}, {123, 456, 7}}
	limit := new(big.Int).SetUint64(math.MaxUint64)
	for _, c := range cases {
		n := new(big.Int).Mul(new(big.Int).SetUint64(c[0]), new(big.Int).SetUint64(c[1]))
		q, r := new(big.Int), new(big.Int)
		q.QuoRem(n, new(big.Int).SetUint64(c[2]), r)
		want := new(big.Int).Set(q)
		if want.Cmp(limit) > 0 {
			want.Set(limit)
		}
		if got := bbrMulDiv(c[0], c[1], c[2]); got != want.Uint64() {
			t.Fatalf("mul/div=%d, expected=%s", got, want)
		}
		if r.Sign() != 0 {
			q.Add(q, big.NewInt(1))
		}
		if q.Cmp(limit) > 0 {
			q.Set(limit)
		}
		if got := bbrMulDivCeil(c[0], c[1], c[2]); got != q.Uint64() {
			t.Fatal("incorrect ceiling division")
		}
	}
	if bdpFromRttAndBandwidth(100*time.Millisecond, 100_000_000_000) != 1_250_000_000 {
		t.Fatal("BDP overflow")
	}
	m := newMaxAckHeightTracker(10)
	now := monotime.Now()
	m.Update(0, 1, now, protocol.MaxByteCount-10)
	if m.Update(0, 2, now.Add(time.Nanosecond), 1280) != protocol.MaxByteCount {
		t.Fatal("ACK aggregation overflow")
	}
}

func TestBBRAckAggregationAndA0(t *testing.T) {
	m := newMaxAckHeightTracker(10)
	now := monotime.Now()
	m.Update(1000, 7, now, 1280)
	m.Update(1000, 8, now.Add(time.Millisecond), 1280)
	if m.Get() != 2560 {
		t.Fatal("ACK burst was not recorded")
	}
	m.Update(1_000_000, 19, now.Add(time.Second), 64)
	m.Update(1_000_000, 20, now.Add(time.Second+time.Nanosecond), 64)
	if m.Get() != 128 {
		t.Fatal("old ACK burst did not expire")
	}
	b := newBandwidthSampler(10)
	if !reflect.ValueOf(b.a0Candidates).IsZero() {
		t.Fatal("disabled A0 tracking allocated storage")
	}
	b.EnableOverestimateAvoidance()
	for i := 1; i <= 4; i++ {
		b.a0Candidates.PushBack(ackPoint{ackTime: now, totalBytesAcked: protocol.ByteCount(i * 10)})
	}
	var a0 ackPoint
	if !b.chooseA0Point(40, &a0) || a0.totalBytesAcked != 40 || b.a0Candidates.Len() != 1 {
		t.Fatal("old A0 candidates were retained")
	}
}

func TestBBRStartupLossDoesNotCountAsRound(t *testing.T) {
	b, inflight := newTestBBR(10_000_000)
	b.maxBandwidth.Update(1_000_000, 1)
	b.bandwidthAtLastRound = 1_000_000
	now := monotime.Now()
	for pn := protocol.PacketNumber(1); pn <= 8; pn++ {
		b.OnPacketSent(now, 0, pn, 1280, true)
		b.OnCongestionEvent(pn, 1280, 1280)
		*inflight = 0
		b.OnAcksEnd(1280, now.Add(time.Millisecond))
	}
	if b.roundsWithoutBandwidthGain != 0 || b.isAtFullBandwidth {
		t.Fatal("loss-only events were counted as RTT rounds")
	}
}

func TestBBRPacingModelAndInitialization(t *testing.T) {
	b, _ := newTestBBR(100_000_000)
	b.rttStats.SetInitialRTT(20 * time.Millisecond)
	if b.pacingRate() < 47_267_839 || b.pacingRate() > 47_267_840 {
		t.Fatal("initial pacing ignored the restored RTT")
	}
	b, _ = newTestBBR(10_000_000)
	b.rttStats.UpdateRTT(20*time.Millisecond, 0)
	if b.pacingRate() != 10_000_000 {
		t.Fatal("initial pacing did not use the measured RTT")
	}
	b.minRtt = 100 * time.Millisecond
	b.maxBandwidth.Update(20_000_000, 1)
	b.isAtFullBandwidth = true
	b.pacingGain = 0.75
	b.calculatePacingRate(monotime.Now())
	if b.bandwidthEstimate() != 20_000_000 || b.getTargetCongestionWindow(2) != 500_000 || b.pacingRate() != 10_000_000 {
		t.Fatal("pacing cap changed the bandwidth model")
	}
	b, _ = newTestBBR(100_000_000)
	b.maxBandwidth.Update(2_000_000, 1)
	b.calculatePacingRate(monotime.Now())
	if b.pacingRate() < 5_769_999 || b.pacingRate() > 5_770_000 {
		t.Fatalf("unexpected STARTUP rate %d, bandwidth %d, RTT %s", b.pacingRate(), b.bandwidthEstimate(), b.rttStats.MinRTT())
	}
	rate := b.pacingRate()
	b.maxBandwidth.Update(1_000_000, 20)
	b.calculatePacingRate(monotime.Now())
	if b.pacingRate() != rate {
		t.Fatal("STARTUP pacing decreased")
	}
	b.isAtFullBandwidth = true
	b.pacingGain = 1
	b.calculatePacingRate(monotime.Now())
	if b.pacingRate() != 1_000_000 {
		t.Fatal("steady pacing did not follow the bandwidth estimate")
	}
}

func TestBBRGainCycleAtPacingLimit(t *testing.T) {
	for _, cap := range []Bandwidth{10_000_000, 100_000_000} {
		b, inflight := newTestBBR(cap)
		b.mode = bbrModeProbeBw
		b.isAtFullBandwidth = true
		b.minRtt = 100 * time.Millisecond
		b.maxBandwidth.Update(10_000_000, 1)
		b.pacingGain = 1.25
		b.cycleCurrentOffset = 0
		b.lastCycleStart = monotime.Now()
		*inflight = 125_000
		b.updateGainCyclePhase(b.lastCycleStart.Add(99*time.Millisecond), *inflight, false)
		if b.cycleCurrentOffset != 0 {
			t.Fatal("probe phase ended before one RTT")
		}
		b.updateGainCyclePhase(b.lastCycleStart.Add(101*time.Millisecond), *inflight, false)
		if cap == 100_000_000 {
			if b.cycleCurrentOffset != 0 {
				t.Fatal("uncapped probe ignored its inflight target")
			}
			continue
		}
		if b.cycleCurrentOffset != 1 {
			t.Fatal("capped probe was stuck waiting for an unreachable target")
		}
		b.updateGainCyclePhase(b.lastCycleStart.Add(time.Millisecond), *inflight, false)
		if b.cycleCurrentOffset != 2 {
			t.Fatal("drain continued after reaching one BDP")
		}
	}
}

func TestBBRStartupPacingLimitRequiresDelivery(t *testing.T) {
	for _, tc := range []struct {
		name       string
		bytes      protocol.ByteCount
		appLimited bool
		capped     bool
		wantFull   bool
	}{{"delivered", 12_000, false, true, true}, {"pacing_only", 4000, false, true, false}, {"application_limited", 12_000, true, true, false}, {"not_capped", 12_000, false, false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := newTestBBR(1_000_000)
			b.minRtt = 100 * time.Millisecond
			b.startupRoundStart = monotime.Now()
			for round := 1; round <= 2; round++ {
				b.startupRoundPacingLimited = tc.capped
				b.lastSampleIsAppLimited = tc.appLimited
				b.checkIfPacingLimitReached(b.startupRoundStart.Add(100*time.Millisecond), tc.bytes, true)
				if round == 1 && b.isAtFullBandwidth {
					t.Fatal("one delivery round ended STARTUP")
				}
			}
			if b.isAtFullBandwidth != tc.wantFull {
				t.Fatal("incorrect delivery-based STARTUP exit")
			}
		})
	}
	b, _ := newTestBBR(1_000_000)
	b.OnApplicationLimited(0)
	now := monotime.Now()
	b.OnPacketSent(now, 0, 1, 1280, true)
	b.OnPacketAcked(1, 1280, 1280, now.Add(time.Millisecond))
	b.OnAcksEnd(1280, now.Add(time.Millisecond))
	if !b.lastSampleIsAppLimited || b.isAtFullBandwidth {
		t.Fatal("a fast ACK cleared the application-limited state")
	}
}

func TestBBRStartupLossExit(t *testing.T) {
	b, _ := newTestBBR(100_000_000)
	b.maxBandwidth.Update(10_000_000, 1)
	b.bandwidthAtLastRound = 1_000_000
	b.numLossEventsInRound = 8
	b.bytesLostInRound = 3000
	state := sendTimeState{isValid: true, bytesInFlight: 100_000}
	b.checkIfFullBandwidthReached(&state)
	if b.isAtFullBandwidth {
		t.Fatal("loss interrupted a growing STARTUP round")
	}
	b.checkIfFullBandwidthReached(&state)
	if !b.isAtFullBandwidth {
		t.Fatal("loss above two percent did not end a plateau")
	}
}

func TestBBRPacerRateChanges(t *testing.T) {
	for _, debt := range []protocol.ByteCount{0, 1280} {
		p := newBBRPacer(1280)
		now := monotime.Now()
		p.SentPacket(now, 12_800+debt, 1_000_000)
		at := now.Add(8 * time.Millisecond)
		p.SetRate(at, 2_000_000)
		if p.Budget(at, 2_000_000) != 1000-debt || p.Budget(at.Add(8*time.Millisecond), 2_000_000) != 3000-debt {
			t.Fatal("rate change retroactively changed the pacing budget")
		}
		if debt > 0 {
			next := p.TimeUntilSend(2_000_000)
			if p.Budget(next, 2_000_000) < 1280 || p.Budget(next.Add(-time.Nanosecond), 2_000_000) >= 1280 {
				t.Fatal("rate change discarded pacing debt")
			}
		}
	}
}

func TestBBRProbeRTTLifecycle(t *testing.T) {
	for _, full := range []bool{false, true} {
		b, inflight := newTestBBR(10_000_000)
		now := monotime.Now()
		b.maxBandwidth.Update(10_000_000, 0)
		b.isAtFullBandwidth = full
		if full {
			b.enterProbeBandwidthMode(now)
		}
		b.minRtt = 50 * time.Millisecond
		b.minRttTimestamp = now.Add(-11 * time.Second)
		pn := protocol.PacketNumber(0)
		sendAndAck := func(sent monotime.Time) monotime.Time {
			pn++
			b.OnPacketSent(sent, *inflight, pn, 1280, true)
			*inflight += 1280
			prior := *inflight
			at := sent.Add(50 * time.Millisecond)
			b.OnPacketAcked(pn, 1280, prior, at)
			*inflight -= 1280
			b.OnAcksEnd(prior, at)
			return at
		}
		first := sendAndAck(now)
		if b.mode != bbrModeProbeRtt || b.GetCongestionWindow() != 5120 {
			t.Fatal("expired minRTT did not enter ProbeRTT")
		}
		sendAndAck(first.Add(time.Millisecond))
		if b.mode != bbrModeProbeRtt || !b.probeRttRoundPassed {
			t.Fatal("ProbeRTT did not wait for its duration and a round")
		}
		last := sendAndAck(first.Add(201 * time.Millisecond))
		expected := bbrMode(bbrModeStartup)
		if full {
			expected = bbrModeProbeBw
		}
		if b.mode != expected || b.minRttTimestamp != last || b.roundsAtPacingLimit != 0 {
			t.Fatal("ProbeRTT did not restore the correct mode")
		}
		if full {
			b.OnApplicationLimited(0)
			sendAndAck(last.Add(11 * time.Second))
			if b.mode == bbrModeProbeRtt {
				t.Fatal("idle restart unnecessarily entered ProbeRTT")
			}
		}
	}
}
