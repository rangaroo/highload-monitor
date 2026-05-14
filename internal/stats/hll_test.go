package stats

import (
	"testing"
)

func TestHLLCardinality(t *testing.T) {
	tests := []struct {
		name     string
		distinct int
		maxErr   float64
	}{
		{
			name:     "100 elements",
			distinct: 100,
			maxErr:   0.05, // 5%
		},
		{
			name:     "1000 elements",
			distinct: 1000,
			maxErr:   0.02, // 2%
		},
		{
			name:     "10000 elements",
			distinct: 10000,
			maxErr:   0.02,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHLL()
			for i := 0; i < tt.distinct; i++ {
				b := []byte{
					byte(i >> 24),
					byte(i >> 16),
					byte(i >> 8),
					byte(i),
				}
				h.Add(b)
			}

			est := h.Estimate()
			expected := uint64(tt.distinct)
			err := float64(int64(est)-int64(expected)) / float64(expected)
			if err < 0 {
				err = -err
			}

			if err > tt.maxErr {
				t.Fatalf("estimate %d, expected %d, error %.2f%% (max %.2f%%)",
					est, expected, err*100, tt.maxErr*100)
			}
		})
	}
}

func TestHLLReset(t *testing.T) {
	h := NewHLL()
	for i := 0; i < 100; i++ {
		b := []byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}
		h.Add(b)
	}
	est1 := h.Estimate()
	if est1 < 90 || est1 > 110 {
		t.Fatalf("initial estimate %d seems off", est1)
	}

	h.Reset()
	est2 := h.Estimate()
	if est2 != 0 {
		t.Fatalf("after reset, estimate %d, want 0", est2)
	}
}
