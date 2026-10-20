package ackhandler

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

type recordedBBR struct {
	bbrController
	inflight protocol.ByteCount
	flushes  int
	neutered []protocol.PacketNumber
}

func (r *recordedBBR) OnPacketSent(now monotime.Time, inflight protocol.ByteCount, pn protocol.PacketNumber, size protocol.ByteCount, ack bool) {
	r.inflight = inflight
	if r.bbrController != nil {
		r.bbrController.OnPacketSent(now, inflight, pn, size, ack)
	}
}

func (r *recordedBBR) OnAcksEnd(prior protocol.ByteCount, now monotime.Time) {
	r.flushes++
	r.bbrController.OnAcksEnd(prior, now)
}

func (r *recordedBBR) OnPacketNeutered(pn protocol.PacketNumber) {
	r.neutered = append(r.neutered, pn)
	r.bbrController.OnPacketNeutered(pn)
}

func testBBRHandler(rate congestion.Bandwidth) SentPacketHandler {
	return NewSentPacketHandlerWithPacingRate(0, 1280, utils.NewRTTStats(), &utils.ConnectionStats{}, true, true, nil, protocol.PerspectiveClient, rate, nil, utils.DefaultLogger)
}

func sendBBRTestPacket(h SentPacketHandler, now monotime.Time) protocol.PacketNumber {
	pn := h.PopPacketNumber(protocol.PacketNumberSpaceInitial)
	h.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionInitial, protocol.ECNNon, 1280, false, false)
	return pn
}

func TestBBRSelectionAndECN(t *testing.T) {
	if _, ok := testBBRHandler(0).(*sentPacketHandler); !ok {
		t.Fatal("zero pacing rate did not select the default sender")
	}
	h := testBBRHandler(1_000_000).(*bbrPacketHandler)
	if h.enableECN || h.ecnTracker != nil || h.ECNMode(true) != protocol.ECNUnsupported {
		t.Fatal("BBRv1 advertised unsupported ECN behavior")
	}
	r := &recordedBBR{}
	a := &bbrSendAdapter{r}
	a.OnPacketSent(monotime.Now(), 1280, 1, 1280, true)
	if r.inflight != 0 {
		t.Fatal("post-send inflight was not translated")
	}
}

func TestBBRHandlerReorderedAcks(t *testing.T) {
	h := testBBRHandler(1000).(*bbrPacketHandler)
	now := monotime.Now()
	pn1 := sendBBRTestPacket(h, now)
	pn2 := sendBBRTestPacket(h, now.Add(time.Millisecond))
	for i, pn := range []protocol.PacketNumber{pn2, pn1} {
		_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.EncryptionInitial, now.Add(time.Duration(100+i)*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
	}
	if h.bytesInFlight != 0 || h.congestion.GetCongestionWindow() != 34*1280 {
		t.Fatal("reordered ACKs lost a bandwidth sample")
	}
}

func TestBBRHandlerAckFlush(t *testing.T) {
	h := testBBRHandler(1_000_000).(*bbrPacketHandler)
	r := &recordedBBR{bbrController: h.controller()}
	h.congestion = r
	now := monotime.Now()
	pn := sendBBRTestPacket(h, now)
	ack := &wire.AckFrame{AckRanges: ackRanges(pn)}
	if _, err := h.ReceivedAck(ack, protocol.EncryptionInitial, now.Add(100*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if r.flushes != 1 {
		t.Fatalf("new ACK flushed %d times", r.flushes)
	}
	cwnd := h.congestion.GetCongestionWindow()
	if _, err := h.ReceivedAck(ack, protocol.EncryptionInitial, now.Add(101*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if r.flushes != 2 || h.congestion.GetCongestionWindow() != cwnd {
		t.Fatal("empty ACK batch was skipped or counted twice")
	}
}

func TestBBRHandlerLossTimer(t *testing.T) {
	h := testBBRHandler(10_000_000).(*bbrPacketHandler)
	r := &recordedBBR{bbrController: h.controller()}
	h.congestion = r
	now := monotime.Now()
	sendBBRTestPacket(h, now.Add(-time.Second))
	sendBBRTestPacket(h, now.Add(-10*time.Millisecond))
	pn := sendBBRTestPacket(h, now)
	_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, protocol.EncryptionInitial, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	before := r.flushes
	if err := h.OnLossDetectionTimeout(h.GetLossDetectionTimeout()); err != nil {
		t.Fatal(err)
	}
	if r.flushes != before+1 || h.bytesInFlight != 0 {
		t.Fatal("loss timer did not flush BBR")
	}
}

func TestBBRHandlerDiscardRetryAndMigration(t *testing.T) {
	h := testBBRHandler(1_000_000).(*bbrPacketHandler)
	r := &recordedBBR{bbrController: h.controller()}
	h.congestion = r
	now := monotime.Now()
	pn := sendBBRTestPacket(h, now)
	if !h.QueueProbePacket(protocol.PacketNumberSpaceInitial) || len(r.neutered) != 1 || r.neutered[0] != pn {
		t.Fatal("PTO removal did not discard its sample")
	}
	sendBBRTestPacket(h, now)
	h.DropPackets(protocol.EncryptionInitial, now)
	if len(r.neutered) != 2 || h.bytesInFlight != 0 {
		t.Fatal("key discard retained a sample")
	}
	h = testBBRHandler(1_000_000).(*bbrPacketHandler)
	sendBBRTestPacket(h, now.Add(-20*time.Millisecond))
	before := h.congestion
	h.ResetForRetry(now)
	if h.congestion == before || h.bytesInFlight != 0 {
		t.Fatal("Retry retained BBR state")
	}
	h.MigratedPath(now, 1200)
	if h.maxPacingRate != 1_000_000 || h.congestion.GetCongestionWindow() != 32*1200 || h.enableECN {
		t.Fatal("migration lost BBR configuration")
	}
}
