package ackhandler

import (
	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlogwriter"
)

type bbrController interface {
	congestion.SendAlgorithmWithDebugInfos
	congestion.HandleAggregatedAcks
	OnApplicationLimited(protocol.ByteCount)
	OnPacketNeutered(protocol.PacketNumber)
	RemoveObsoletePackets(protocol.PacketNumber)
}

type bbrSendAdapter struct {
	bbrController
}

func (a *bbrSendAdapter) OnPacketSent(now monotime.Time, inflight protocol.ByteCount, pn protocol.PacketNumber, size protocol.ByteCount, ackEliciting bool) {
	if ackEliciting {
		inflight -= size
	}
	a.bbrController.OnPacketSent(now, inflight, pn, size, ackEliciting)
}

type bbrPacketHandler struct {
	*sentPacketHandler
	maxDatagramSize protocol.ByteCount
}

var _ SentPacketHandler = &bbrPacketHandler{}

func NewSentPacketHandlerWithPacingRate(
	initialPN protocol.PacketNumber,
	initialMaxDatagramSize protocol.ByteCount,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	clientAddressValidated bool,
	enableECN bool,
	ignorePacketsBelow func(protocol.PacketNumber),
	pers protocol.Perspective,
	rate congestion.Bandwidth,
	tracer qlogwriter.Recorder,
	logger utils.Logger,
) SentPacketHandler {
	h := newSentPacketHandler(initialPN, initialMaxDatagramSize, rttStats, connStats, clientAddressValidated, enableECN, ignorePacketsBelow, pers, rate, tracer, logger).(*sentPacketHandler)
	if rate == 0 {
		return h
	}
	return &bbrPacketHandler{sentPacketHandler: h, maxDatagramSize: initialMaxDatagramSize}
}

func (h *sentPacketHandler) resetCongestionController(size protocol.ByteCount) {
	if h.maxPacingRate > 0 {
		h.enableECN = false
		h.ecnTracker = nil
		h.congestion = &bbrSendAdapter{congestion.NewBbrSender(h.rttStats, size, h.maxPacingRate, func() protocol.ByteCount { return h.bytesInFlight }, h.connStats)}
		return
	}
	h.congestion = congestion.NewCubicSender(congestion.DefaultClock{}, h.rttStats, h.connStats, size, true, h.qlogger)
}

func (h *bbrPacketHandler) controller() bbrController {
	return h.congestion.(bbrController)
}

func (h *bbrPacketHandler) OnApplicationLimited() {
	h.controller().OnApplicationLimited(h.bytesInFlight)
}

func (h *bbrPacketHandler) ReceivedAck(ack *wire.AckFrame, level protocol.EncryptionLevel, now monotime.Time) (bool, error) {
	acked, err := h.sentPacketHandler.ReceivedAck(ack, level, now)
	if err == nil {
		h.controller().RemoveObsoletePackets(h.hist.FirstPacketNumber())
	}
	return acked, err
}

func (h *bbrPacketHandler) OnLossDetectionTimeout(now monotime.Time) error {
	prior := h.bytesInFlight
	if err := h.sentPacketHandler.OnLossDetectionTimeout(now); err != nil {
		return err
	}
	h.controller().OnAcksEnd(prior, now)
	h.controller().RemoveObsoletePackets(h.hist.FirstPacketNumber())
	return nil
}

func (h *bbrPacketHandler) DropPackets(level protocol.EncryptionLevel, now monotime.Time) {
	for pn, p := range h.hist.Packets() {
		if p.EncryptionLevel == level {
			h.controller().OnPacketNeutered(pn)
		}
	}
	h.sentPacketHandler.DropPackets(level, now)
	h.controller().RemoveObsoletePackets(h.hist.FirstPacketNumber())
}

func (h *bbrPacketHandler) QueueProbePacket(space protocol.PacketNumberSpace) bool {
	pn, _ := h.hist.FirstOutstanding(space)
	if !h.sentPacketHandler.QueueProbePacket(space) {
		return false
	}
	h.controller().OnPacketNeutered(pn)
	return true
}

func (h *bbrPacketHandler) ResetForRetry(now monotime.Time) {
	h.sentPacketHandler.ResetForRetry(now)
	h.resetCongestionController(h.maxDatagramSize)
}

func (h *bbrPacketHandler) SetMaxDatagramSize(size protocol.ByteCount) {
	h.sentPacketHandler.SetMaxDatagramSize(size)
	h.maxDatagramSize = max(h.maxDatagramSize, size)
}

func (h *bbrPacketHandler) MigratedPath(now monotime.Time, size protocol.ByteCount) {
	h.sentPacketHandler.MigratedPath(now, size)
	h.maxDatagramSize = size
}
