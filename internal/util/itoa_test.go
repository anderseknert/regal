package util_test

import (
	"testing"

	"github.com/open-policy-agent/regal/internal/util"
)

func TestItoa(t *testing.T) {
	assertItoa(t, 1, "1")
	assertItoa(t, 10, "10")
	assertItoa(t, 99, "99")
	assertItoa(t, 100, "100")
	assertItoa(t, 111, "111")
	assertItoa(t, 222, "222")
	assertItoa(t, 200, "200")
	assertItoa(t, 555, "555") // strconv.Itoa (allocates)
}

func BenchmarkItoa(b *testing.B) {
	for b.Loop() {
		for i := range 500 {
			_ = util.Itoa(i)
		}
	}
}

func assertItoa(t *testing.T, i int, exp string) {
	t.Helper()

	if act := util.Itoa(i); exp != act {
		t.Fatalf("for input %d, expected string %s, got %s", i, exp, act)
	}
}
