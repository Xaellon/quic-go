package congestion

import (
	"math"
	"math/bits"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
)

func bbrMulDiv(a, b, divisor uint64) uint64 {
	if divisor == 0 {
		return math.MaxUint64
	}
	hi, lo := bits.Mul64(a, b)
	if hi >= divisor {
		return math.MaxUint64
	}
	q, _ := bits.Div64(hi, lo, divisor)
	return q
}

func bbrMulDivCeil(a, b, divisor uint64) uint64 {
	if divisor == 0 {
		return math.MaxUint64
	}
	hi, lo := bits.Mul64(a, b)
	if hi >= divisor {
		return math.MaxUint64
	}
	q, r := bits.Div64(hi, lo, divisor)
	if r != 0 && q != math.MaxUint64 {
		q++
	}
	return q
}

func bbrBandwidthFromDelta(size protocol.ByteCount, delta time.Duration) Bandwidth {
	if size <= 0 || delta <= 0 {
		return 0
	}
	return Bandwidth(bbrMulDiv(uint64(size), 8*uint64(time.Second), uint64(delta)))
}

func bbrScaleBandwidth(rate Bandwidth, gain float64) Bandwidth {
	value := float64(rate) * gain
	if value >= float64(uint64(math.MaxUint64)) {
		return Bandwidth(math.MaxUint64)
	}
	if value <= 0 {
		return 0
	}
	return max(1, Bandwidth(value))
}

func bbrScaleBytes(size protocol.ByteCount, gain float64) protocol.ByteCount {
	value := float64(size) * gain
	if value >= float64(protocol.MaxByteCount) {
		return protocol.MaxByteCount
	}
	if value <= 0 {
		return 0
	}
	return protocol.ByteCount(value)
}

func bbrAddBytes(a, b protocol.ByteCount) protocol.ByteCount {
	return a + min(b, protocol.MaxByteCount-a)
}

func bdpFromRttAndBandwidth(rtt time.Duration, bandwidth Bandwidth) protocol.ByteCount {
	if rtt <= 0 {
		return 0
	}
	return protocol.ByteCount(min(uint64(protocol.MaxByteCount), bbrMulDiv(uint64(bandwidth), uint64(rtt), 8*uint64(time.Second))))
}
