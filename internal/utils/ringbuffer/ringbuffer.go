package ringbuffer

type RingBuffer[T any] struct {
	ring    []T
	headPos int
}

func (r *RingBuffer[T]) Init(size int) {
	r.ring = make([]T, 0, size)
	r.headPos = 0
}

func (r *RingBuffer[T]) Len() int {
	return len(r.ring)
}

func (r *RingBuffer[T]) Empty() bool {
	return len(r.ring) == 0
}

func (r *RingBuffer[T]) PushBack(t T) {
	if len(r.ring) == cap(r.ring) {
		r.grow()
	}
	tailPos := r.headPos + len(r.ring)
	if tailPos >= cap(r.ring) {
		tailPos -= cap(r.ring)
	}

	r.ring = r.ring[:len(r.ring)+1]
	r.ring[:cap(r.ring)][tailPos] = t
}

func (r *RingBuffer[T]) PopFront() T {
	if r.Empty() {
		panic("github.com/quic-go/quic-go/internal/utils/ringbuffer: pop from an empty queue")
	}

	r.ring = r.ring[:len(r.ring)-1]
	t := r.ring[:cap(r.ring)][r.headPos]
	clear(r.ring[:cap(r.ring)][r.headPos : r.headPos+1])
	r.headPos++
	if r.headPos == cap(r.ring) {
		r.headPos = 0
	}
	return t
}

func (r *RingBuffer[T]) PeekFront() T {
	if r.Empty() {
		panic("github.com/quic-go/quic-go/internal/utils/ringbuffer: peek from an empty queue")
	}
	return r.ring[:cap(r.ring)][r.headPos]
}

func (r *RingBuffer[T]) Offset(index int) *T {
	if index < 0 || index >= r.Len() {
		panic("github.com/quic-go/quic-go/internal/utils/ringbuffer: offset from invalid index")
	}

	pos := r.headPos + index
	if pos >= cap(r.ring) {
		pos -= cap(r.ring)
	}

	return &r.ring[:cap(r.ring)][pos]
}

func (r *RingBuffer[T]) grow() {
	oldRing := r.ring
	newSize := cap(oldRing) * 2
	if newSize == 0 {
		newSize = 1
	}
	newRing := make([]T, len(oldRing), newSize)
	headLen := copy(newRing, oldRing[r.headPos:])
	copy(newRing[headLen:], oldRing[:r.headPos])
	r.ring = newRing
	r.headPos = 0
}

func (r *RingBuffer[T]) Clear() {
	clear(r.ring[:cap(r.ring)])
	r.ring = r.ring[:0]
	r.headPos = 0
}
