package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"go.uber.org/mock/gomock"
)

type bbrTestPacketNumbers struct {
	packetNumberManager
	limited int
}

func (p *bbrTestPacketNumbers) OnApplicationLimited() { p.limited++ }

func TestPacketPackerBBRApplicationLimited(t *testing.T) {
	t.Run("1-RTT", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveServer)
		pn := &bbrTestPacketNumbers{packetNumberManager: tp.pnManager}
		tp.packer.pnManager = pn
		tp.pnManager.EXPECT().PeekPacketNumber(protocol.PacketNumberSpaceAppData).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
		tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(ctrl), nil)
		tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true)
		tp.framer.EXPECT().HasData().Times(2)
		buf := getPacketBuffer()
		defer buf.Release()
		_, err := tp.packer.AppendPacket(buf, 1280, monotime.Now(), protocol.Version1)
		if err != errNothingToPack || pn.limited != 1 {
			t.Fatal("empty 1-RTT packing did not report application limitation")
		}
	})
	t.Run("handshake", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveServer)
		pn := &bbrTestPacketNumbers{packetNumberManager: tp.pnManager}
		tp.packer.pnManager = pn
		tp.framer.EXPECT().HasData()
		tp.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
		tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
		tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
		packet, err := tp.packer.PackCoalescedPacket(false, 1280, monotime.Now(), protocol.Version1)
		if err != nil || packet != nil || pn.limited != 1 {
			t.Fatal("empty handshake packing did not report application limitation")
		}
	})
	t.Run("queued data", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveServer)
		pn := &bbrTestPacketNumbers{packetNumberManager: tp.pnManager}
		tp.packer.pnManager = pn
		tp.framer.EXPECT().HasData().Return(true)
		tp.packer.onApplicationLimited()
		if pn.limited != 0 {
			t.Fatal("queued data was marked application limited")
		}
	})
}
