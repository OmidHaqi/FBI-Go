package routing

import (
	"errors"
	"fmt"
	"github.com/omidhaqi/FBI-Go/internal/health"
	"github.com/omidhaqi/FBI-Go/internal/policy"
)

// ManagedWeights translates an explicit application policy into M2's new-flow
// selection weights. A separate namespace is required per managed application.
// SYSTEM_DEFAULT must use that namespace's ordinary routing without M2 applied.
// An unavailable STRICT WAN returns an error before the application is started.
func ManagedWeights(app policy.ApplicationPolicy, global policy.GlobalPolicy, wans []policy.WAN) (map[string]int, bool, error) {
	if err := app.Validate(); err != nil {
		return nil, false, err
	}
	if !app.Enabled {
		return nil, false, errors.New("managed application policy is disabled")
	}
	if len(wans) == 0 {
		return nil, false, errors.New("no managed WANs")
	}
	byID := make(map[string]policy.WAN, len(wans))
	weights := make(map[string]int, len(wans))
	for _, w := range wans {
		if w.ID == "" || w.Interface == "" || byID[w.ID].ID != "" {
			return nil, false, errors.New("invalid or duplicate managed WAN")
		}
		if _, exists := weights[w.Interface]; exists {
			return nil, false, errors.New("duplicate managed interface")
		}
		byID[w.ID] = w
		weights[w.Interface] = 0
	}
	usable := func(id string) bool {
		w, ok := byID[id]
		return ok && w.Enabled && w.Health != health.Offline && w.Health != health.Unknown
	}
	switch app.Mode {
	case policy.SystemDefault:
		return nil, true, nil
	case policy.PinnedWAN:
		selected := app.PreferredWAN
		if !usable(selected) {
			if app.FailureBehavior != policy.Failover || !usable(app.FallbackWAN) {
				return nil, false, fmt.Errorf("managed WAN %q unavailable; launch refused", selected)
			}
			selected = app.FallbackWAN
		}
		weights[byID[selected].Interface] = 1
	case policy.Auto:
		allowed := make(map[string]bool, len(global.EligibleWANs))
		for _, id := range global.EligibleWANs {
			allowed[id] = true
		}
		for _, w := range wans {
			if !allowed[w.ID] || !usable(w.ID) || global.ExcludeDegraded && w.Health == health.Degraded {
				continue
			}
			weight := w.Weight
			if configured, ok := global.Weights[w.ID]; ok {
				weight = configured
			}
			if weight < 0 {
				return nil, false, fmt.Errorf("negative weight for %s", w.ID)
			}
			weights[w.Interface] = weight
		}
	default:
		return nil, false, fmt.Errorf("unsupported application mode %q", app.Mode)
	}
	total := 0
	for _, weight := range weights {
		total += weight
	}
	if total == 0 || total > 256 {
		return nil, false, errors.New("managed routing has no eligible weighted WAN or exceeds 256 slots")
	}
	return weights, false, nil
}
