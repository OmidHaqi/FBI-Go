package policy

import (
	"github.com/omidhaqi/FBI-Go/internal/health"
	"testing"
)

func TestPrecedenceAndFailure(t *testing.T) {
	w := []WAN{{ID: "wifi", Enabled: true, Health: health.Healthy, Weight: 1}, {ID: "eth", Enabled: true, Health: health.Healthy, Weight: 1}}
	g := GlobalPolicy{Mode: Auto, EligibleWANs: []string{"eth", "wifi"}}
	a := &ApplicationPolicy{ID: "desktop:firefox", Mode: PinnedWAN, PreferredWAN: "wifi", FailureBehavior: Strict, Enabled: true}
	d, e := Decide(a, g, w, 0)
	if e != nil || d.SelectedWAN != "wifi" {
		t.Fatalf("%+v %v", d, e)
	}
	w[0].Health = health.Offline
	d, e = Decide(a, g, w, 0)
	if e != nil || d.SelectedWAN != "" || d.AppliedPolicy != PinnedWAN {
		t.Fatalf("strict: %+v %v", d, e)
	}
	a.FailureBehavior = Failover
	a.FallbackWAN = "eth"
	d, e = Decide(a, g, w, 0)
	if e != nil || d.SelectedWAN != "eth" || !d.Fallback {
		t.Fatalf("failover: %+v %v", d, e)
	}
}
func TestValidation(t *testing.T) {
	a := ApplicationPolicy{ID: "x", Mode: PinnedWAN, PreferredWAN: "a", FallbackWAN: "a", FailureBehavior: Failover}
	if a.Validate() == nil {
		t.Fatal("same fallback accepted")
	}
}
