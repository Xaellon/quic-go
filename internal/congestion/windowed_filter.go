package congestion

import "cmp"

type filterEntry[T cmp.Ordered] struct {
	sample T
	round  roundTripCount
}

type windowedFilter[T cmp.Ordered] struct {
	windowLength roundTripCount
	estimates    [3]filterEntry[T]
}

func newWindowedFilter[T cmp.Ordered](length roundTripCount) *windowedFilter[T] {
	return &windowedFilter[T]{windowLength: length}
}

func (f *windowedFilter[T]) GetBest() T {
	return f.estimates[0].sample
}

func (f *windowedFilter[T]) Update(sample T, round roundTripCount) {
	var zero T
	if f.estimates[0].sample == zero || sample >= f.estimates[0].sample || round-f.estimates[2].round > f.windowLength {
		f.Reset(sample, round)
		return
	}
	if sample >= f.estimates[1].sample {
		f.estimates[1] = filterEntry[T]{sample, round}
		f.estimates[2] = f.estimates[1]
	} else if sample >= f.estimates[2].sample {
		f.estimates[2] = filterEntry[T]{sample, round}
	}
	if round-f.estimates[0].round > f.windowLength {
		f.estimates[0] = f.estimates[1]
		f.estimates[1] = f.estimates[2]
		f.estimates[2] = filterEntry[T]{sample, round}
		if round-f.estimates[0].round > f.windowLength {
			f.estimates[0] = f.estimates[1]
			f.estimates[1] = f.estimates[2]
		}
		return
	}
	if f.estimates[1].sample == f.estimates[0].sample && round-f.estimates[1].round > f.windowLength/4 {
		f.estimates[1] = filterEntry[T]{sample, round}
		f.estimates[2] = f.estimates[1]
		return
	}
	if f.estimates[2].sample == f.estimates[1].sample && round-f.estimates[2].round > f.windowLength/2 {
		f.estimates[2] = filterEntry[T]{sample, round}
	}
}

func (f *windowedFilter[T]) Reset(sample T, round roundTripCount) {
	value := filterEntry[T]{sample, round}
	f.estimates = [3]filterEntry[T]{value, value, value}
}
