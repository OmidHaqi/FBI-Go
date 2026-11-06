package scheduler

import (
	"errors"
	"sort"
)

type Candidate struct {
	ID       string
	Weight   int
	Eligible bool
}

// Select maps a caller-supplied stable flow hash to one weighted candidate.
// Callers must preserve the chosen WAN for the life of a connection.
func Select(candidates []Candidate, hash uint64) (string, error) {
	copyOf := append([]Candidate(nil), candidates...)
	sort.Slice(copyOf, func(i, j int) bool { return copyOf[i].ID < copyOf[j].ID })
	total := uint64(0)
	for _, c := range copyOf {
		if c.Eligible && c.Weight > 0 {
			total += uint64(c.Weight)
		}
	}
	if total == 0 {
		return "", errors.New("no eligible weighted WAN")
	}
	slot := hash % total
	for _, c := range copyOf {
		if !c.Eligible || c.Weight <= 0 {
			continue
		}
		w := uint64(c.Weight)
		if slot < w {
			return c.ID, nil
		}
		slot -= w
	}
	panic("unreachable weighted selection")
}
