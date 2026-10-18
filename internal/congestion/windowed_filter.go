package congestion

import "cmp"

type WindowedFilterValue interface {
	any
}

type WindowedFilterTime interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr |
		~float32 | ~float64
}

type WindowedFilter[V WindowedFilterValue, T WindowedFilterTime] struct {
	windowLength T
	estimates    []entry[V, T]
	comparator   func(V, V) int
}

type entry[V WindowedFilterValue, T WindowedFilterTime] struct {
	sample V
	time   T
}

func Max[T cmp.Ordered](a, b T) T {
	if a < b {
		return b
	}
	return a
}

func Min[T cmp.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

func MaxFilter[O cmp.Ordered](a, b O) int {
	if a > b {
		return 1
	} else if a < b {
		return -1
	}
	return 0
}

func MinFilter[O cmp.Ordered](a, b O) int {
	if a < b {
		return 1
	} else if a > b {
		return -1
	}
	return 0
}

func NewWindowedFilter[V WindowedFilterValue, T WindowedFilterTime](windowLength T, comparator func(V, V) int) *WindowedFilter[V, T] {
	return &WindowedFilter[V, T]{
		windowLength: windowLength,
		estimates:    make([]entry[V, T], 3),
		comparator:   comparator,
	}
}

func (f *WindowedFilter[V, T]) SetWindowLength(windowLength T) {
	f.windowLength = windowLength
}

func (f *WindowedFilter[V, T]) GetBest() V {
	return f.estimates[0].sample
}

func (f *WindowedFilter[V, T]) GetSecondBest() V {
	return f.estimates[1].sample
}

func (f *WindowedFilter[V, T]) GetThirdBest() V {
	return f.estimates[2].sample
}

func (f *WindowedFilter[V, T]) Update(newSample V, newTime T) {
	if f.comparator(f.estimates[0].sample, *new(V)) == 0 ||
		f.comparator(newSample, f.estimates[0].sample) >= 0 ||
		newTime-f.estimates[2].time > f.windowLength {
		f.Reset(newSample, newTime)
		return
	}

	if f.comparator(newSample, f.estimates[1].sample) >= 0 {
		f.estimates[1] = entry[V, T]{newSample, newTime}
		f.estimates[2] = f.estimates[1]
	} else if f.comparator(newSample, f.estimates[2].sample) >= 0 {
		f.estimates[2] = entry[V, T]{newSample, newTime}
	}

	if newTime-f.estimates[0].time > f.windowLength {
		f.estimates[0] = f.estimates[1]
		f.estimates[1] = f.estimates[2]
		f.estimates[2] = entry[V, T]{newSample, newTime}

		if newTime-f.estimates[0].time > f.windowLength {
			f.estimates[0] = f.estimates[1]
			f.estimates[1] = f.estimates[2]
		}
		return
	}

	if f.comparator(f.estimates[1].sample, f.estimates[0].sample) == 0 &&
		newTime-f.estimates[1].time > f.windowLength/4 {
		f.estimates[1] = entry[V, T]{newSample, newTime}
		f.estimates[2] = f.estimates[1]
		return
	}

	if f.comparator(f.estimates[2].sample, f.estimates[1].sample) == 0 &&
		newTime-f.estimates[2].time > f.windowLength/2 {
		f.estimates[2] = entry[V, T]{newSample, newTime}
	}
}

func (f *WindowedFilter[V, T]) Reset(newSample V, newTime T) {
	f.estimates[2] = entry[V, T]{newSample, newTime}
	f.estimates[1] = f.estimates[2]
	f.estimates[0] = f.estimates[1]
}

func (f *WindowedFilter[V, T]) Clear() {
	f.estimates = make([]entry[V, T], 3)
}
