package congestion

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils/ringbuffer"
)

type entryWrapper[T any] struct {
	present bool
	entry   T
}

type packetNumberIndexedQueue[T any] struct {
	entries                ringbuffer.RingBuffer[entryWrapper[T]]
	numberOfPresentEntries int
	firstPacket            protocol.PacketNumber
}

func newPacketNumberIndexedQueue[T any](size int) *packetNumberIndexedQueue[T] {
	q := &packetNumberIndexedQueue[T]{firstPacket: protocol.InvalidPacketNumber}
	q.entries.Init(size)
	return q
}

func (p *packetNumberIndexedQueue[T]) Emplace(pn protocol.PacketNumber, entry *T) bool {
	if pn == protocol.InvalidPacketNumber || entry == nil {
		return false
	}
	if p.IsEmpty() {
		p.entries.PushBack(entryWrapper[T]{present: true, entry: *entry})
		p.numberOfPresentEntries = 1
		p.firstPacket = pn
		return true
	}
	if pn <= p.LastPacket() {
		return false
	}
	gap := int(pn-p.firstPacket) - p.entries.Len()
	for range gap {
		p.entries.PushBack(entryWrapper[T]{})
	}
	p.entries.PushBack(entryWrapper[T]{present: true, entry: *entry})
	p.numberOfPresentEntries++
	return true
}

func (p *packetNumberIndexedQueue[T]) GetEntry(pn protocol.PacketNumber) *T {
	entry := p.getEntry(pn)
	if entry == nil {
		return nil
	}
	return &entry.entry
}

func (p *packetNumberIndexedQueue[T]) Remove(pn protocol.PacketNumber) bool {
	entry := p.getEntry(pn)
	if entry == nil {
		return false
	}
	entry.present = false
	p.numberOfPresentEntries--
	if pn == p.firstPacket {
		for !p.entries.Empty() && !p.entries.PeekFront().present {
			p.entries.PopFront()
			p.firstPacket++
		}
		if p.entries.Empty() {
			p.firstPacket = protocol.InvalidPacketNumber
		}
	}
	return true
}

func (p *packetNumberIndexedQueue[T]) IsEmpty() bool {
	return p.numberOfPresentEntries == 0
}

func (p *packetNumberIndexedQueue[T]) FirstPacket() protocol.PacketNumber {
	return p.firstPacket
}

func (p *packetNumberIndexedQueue[T]) LastPacket() protocol.PacketNumber {
	if p.IsEmpty() {
		return protocol.InvalidPacketNumber
	}
	return p.firstPacket + protocol.PacketNumber(p.entries.Len()-1)
}

func (p *packetNumberIndexedQueue[T]) getEntry(pn protocol.PacketNumber) *entryWrapper[T] {
	if pn == protocol.InvalidPacketNumber || p.IsEmpty() || pn < p.firstPacket {
		return nil
	}
	offset := pn - p.firstPacket
	if offset >= protocol.PacketNumber(p.entries.Len()) {
		return nil
	}
	entry := p.entries.Offset(int(offset))
	if !entry.present {
		return nil
	}
	return entry
}
