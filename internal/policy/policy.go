package policy

import (
	"errors"
	"fmt"
	"github.com/omidhaqi/FBI-Go/internal/health"
	"github.com/omidhaqi/FBI-Go/internal/scheduler"
)

type Mode string

const (
	Auto          Mode = "AUTO"
	PinnedWAN     Mode = "PINNED_WAN"
	SystemDefault Mode = "SYSTEM_DEFAULT"
)

type FailureBehavior string

const (
	Strict   FailureBehavior = "STRICT"
	Failover FailureBehavior = "FAILOVER"
)

type WAN struct {
	ID              string       `json:"id"`
	Interface       string       `json:"interface"`
	Gateway         string       `json:"gateway"`
	SourceAddresses []string     `json:"source_addresses"`
	Enabled         bool         `json:"enabled"`
	Health          health.State `json:"health"`
	Weight          int          `json:"weight"`
	RoutingTable    int          `json:"routing_table,omitempty"`
}
type ApplicationPolicy struct {
	ID              string          `json:"id"`
	DisplayName     string          `json:"display_name"`
	DesktopEntry    string          `json:"desktop_entry,omitempty"`
	Executable      string          `json:"executable,omitempty"`
	Mode            Mode            `json:"mode"`
	PreferredWAN    string          `json:"preferred_wan,omitempty"`
	FallbackWAN     string          `json:"fallback_wan,omitempty"`
	FailureBehavior FailureBehavior `json:"failure_behavior,omitempty"`
	Enabled         bool            `json:"enabled"`
}
type GlobalPolicy struct {
	Mode            Mode           `json:"mode"`
	EligibleWANs    []string       `json:"eligible_wans"`
	Weights         map[string]int `json:"weights"`
	ExcludeDegraded bool           `json:"exclude_degraded"`
}
type RoutingDecision struct {
	SelectedWAN   string   `json:"selected_wan,omitempty"`
	AppliedPolicy Mode     `json:"applied_policy"`
	Reason        string   `json:"reason"`
	Fallback      bool     `json:"fallback"`
	Diagnostics   []string `json:"diagnostics,omitempty"`
}

func (p ApplicationPolicy) Validate() error {
	if p.ID == "" {
		return errors.New("application ID required")
	}
	switch p.Mode {
	case Auto, SystemDefault:
		if p.PreferredWAN != "" || p.FallbackWAN != "" {
			return errors.New("WAN selection requires PINNED_WAN")
		}
	case PinnedWAN:
		if p.PreferredWAN == "" {
			return errors.New("preferred WAN required")
		}
		if p.FailureBehavior != Strict && p.FailureBehavior != Failover {
			return errors.New("STRICT or FAILOVER required")
		}
		if p.FailureBehavior == Failover && (p.FallbackWAN == "" || p.FallbackWAN == p.PreferredWAN) {
			return errors.New("distinct fallback WAN required")
		}
		if p.FailureBehavior == Strict && p.FallbackWAN != "" {
			return errors.New("STRICT cannot have fallback WAN")
		}
	default:
		return fmt.Errorf("unknown mode %q", p.Mode)
	}
	return nil
}

// Decide applies an explicit managed-app policy first. It does not install routes.
func Decide(app *ApplicationPolicy, global GlobalPolicy, wans []WAN, flowHash uint64) (RoutingDecision, error) {
	byID := map[string]WAN{}
	for _, w := range wans {
		byID[w.ID] = w
	}
	usable := func(id string) bool {
		w, ok := byID[id]
		return ok && w.Enabled && w.Health != health.Offline && w.Health != health.Unknown
	}
	if app != nil && app.Enabled {
		if err := app.Validate(); err != nil {
			return RoutingDecision{}, err
		}
		switch app.Mode {
		case SystemDefault:
			return RoutingDecision{AppliedPolicy: SystemDefault, Reason: "managed application requests system routing"}, nil
		case PinnedWAN:
			if usable(app.PreferredWAN) {
				return RoutingDecision{SelectedWAN: app.PreferredWAN, AppliedPolicy: PinnedWAN, Reason: "explicit managed application policy"}, nil
			}
			if app.FailureBehavior == Failover && usable(app.FallbackWAN) {
				return RoutingDecision{SelectedWAN: app.FallbackWAN, AppliedPolicy: PinnedWAN, Reason: "explicit fallback WAN", Fallback: true}, nil
			}
			return RoutingDecision{AppliedPolicy: PinnedWAN, Reason: "selected WAN unavailable; no permitted fallback", Diagnostics: []string{"enforcement must block new connections for STRICT policy"}}, nil
		}
	}
	if global.Mode == SystemDefault {
		return RoutingDecision{AppliedPolicy: SystemDefault, Reason: "global system routing"}, nil
	}
	if global.Mode != Auto {
		return RoutingDecision{}, fmt.Errorf("unsupported global mode %q", global.Mode)
	}
	allowed := map[string]bool{}
	for _, id := range global.EligibleWANs {
		allowed[id] = true
	}
	var candidates []scheduler.Candidate
	for _, w := range wans {
		weight := w.Weight
		if v, ok := global.Weights[w.ID]; ok {
			weight = v
		}
		candidates = append(candidates, scheduler.Candidate{ID: w.ID, Weight: weight, Eligible: allowed[w.ID] && usable(w.ID) && (!global.ExcludeDegraded || w.Health != health.Degraded)})
	}
	id, err := scheduler.Select(candidates, flowHash)
	if err != nil {
		return RoutingDecision{AppliedPolicy: Auto, Reason: "no eligible WAN", Diagnostics: []string{err.Error()}}, nil
	}
	return RoutingDecision{SelectedWAN: id, AppliedPolicy: Auto, Reason: "weighted automatic selection"}, nil
}
