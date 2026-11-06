package scheduler

import "testing"

func TestWeightedSelection(t *testing.T) {
	c := []Candidate{{ID: "b", Weight: 3, Eligible: true}, {ID: "a", Weight: 1, Eligible: true}, {ID: "off", Weight: 100, Eligible: false}}
	counts := map[string]int{}
	for i := uint64(0); i < 400; i++ {
		id, e := Select(c, i)
		if e != nil {
			t.Fatal(e)
		}
		counts[id]++
	}
	if counts["a"] != 100 || counts["b"] != 300 || counts["off"] != 0 {
		t.Fatal(counts)
	}
}
