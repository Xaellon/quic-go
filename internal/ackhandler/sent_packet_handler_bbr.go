package ackhandler

import (
	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlogwriter"
)

func NewSentPacketHandler(
	initialPN protocol.PacketNumber,
	initialMaxDatagramSize protocol.ByteCount,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	clientAddressValidated bool,
	enableECN bool,
	ignorePacketsBelow func(protocol.PacketNumber),
	pers protocol.Perspective,
	rateOrTracer any,
	tracerOrLogger any,
	legacyLogger ...utils.Logger,
) SentPacketHandler {
	var rate congestion.Bandwidth
	var tracer qlogwriter.Recorder
	var logger utils.Logger
	switch len(legacyLogger) {
	case 0:
		if rateOrTracer != nil {
			tracer = rateOrTracer.(qlogwriter.Recorder)
		}
		if tracerOrLogger != nil {
			logger = tracerOrLogger.(utils.Logger)
		}
	case 1:
		switch value := rateOrTracer.(type) {
		case congestion.Bandwidth:
			rate = value
		case int:
			if value < 0 {
				panic("negative pacing rate")
			}
			rate = congestion.Bandwidth(value)
		default:
			panic("invalid pacing rate")
		}
		if tracerOrLogger != nil {
			tracer = tracerOrLogger.(qlogwriter.Recorder)
		}
		logger = legacyLogger[0]
	default:
		panic("invalid sent packet handler arguments")
	}
	return newSentPacketHandler(
		initialPN,
		initialMaxDatagramSize,
		rttStats,
		connStats,
		clientAddressValidated,
		enableECN,
		ignorePacketsBelow,
		pers,
		rate,
		tracer,
		logger,
	)
}

func (h *sentPacketHandler) resetCongestionController(size protocol.ByteCount) {
	if h.maxPacingRate > 0 {
		h.congestion = congestion.NewBbrSender(
			h.rttStats,
			size,
			h.maxPacingRate,
			func() protocol.ByteCount { return h.bytesInFlight },
			h.connStats,
		)
		return
	}
	h.congestion = congestion.NewCubicSender(
		congestion.DefaultClock{},
		h.rttStats,
		h.connStats,
		size,
		true,
		h.qlogger,
	)
}
