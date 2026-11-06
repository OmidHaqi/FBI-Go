package routing

import (
	"github.com/omidhaqi/FBI-Go/internal/health"
	"github.com/omidhaqi/FBI-Go/internal/policy"
	"reflect"
	"testing"
)

func TestManagedWeights(t *testing.T) {
	wans := []policy.WAN{{ID: "wan-a", Interface: "fbi_ca", Enabled: true, Health: health.Healthy, Weight: 3}, {ID: "wan-b", Interface: "fbi_cb", Enabled: true, Health: health.Healthy, Weight: 1}}
	global := policy.GlobalPolicy{Mode: policy.Auto, EligibleWANs: []string{"wan-a", "wan-b"}}
	tests := []struct {
		name          string
		app           policy.ApplicationPolicy
		mutate        func([]policy.WAN)
		want          map[string]int
		system, fails bool
	}{
		{"pinned overrides auto", policy.ApplicationPolicy{ID: "app", Enabled: true, Mode: policy.PinnedWAN, PreferredWAN: "wan-b", FailureBehavior: policy.Strict}, nil, map[string]int{"fbi_ca": 0, "fbi_cb": 1}, false, false},
		{"strict unavailable refuses launch", policy.ApplicationPolicy{ID: "app", Enabled: true, Mode: policy.PinnedWAN, PreferredWAN: "wan-b", FailureBehavior: policy.Strict}, func(w []policy.WAN) { w[1].Health = health.Offline }, nil, false, true},
		{"explicit failover", policy.ApplicationPolicy{ID: "app", Enabled: true, Mode: policy.PinnedWAN, PreferredWAN: "wan-b", FallbackWAN: "wan-a", FailureBehavior: policy.Failover}, func(w []policy.WAN) { w[1].Health = health.Offline }, map[string]int{"fbi_ca": 1, "fbi_cb": 0}, false, false},
		{"automatic", policy.ApplicationPolicy{ID: "app", Enabled: true, Mode: policy.Auto}, nil, map[string]int{"fbi_ca": 3, "fbi_cb": 1}, false, false},
		{"system routing", policy.ApplicationPolicy{ID: "app", Enabled: true, Mode: policy.SystemDefault}, nil, nil, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copyWANs := append([]policy.WAN(nil), wans...)
			if tt.mutate != nil {
				tt.mutate(copyWANs)
			}
			got, system, err := ManagedWeights(tt.app, global, copyWANs)
			if (err != nil) != tt.fails || system != tt.system || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("weights=%v system=%t err=%v; want %v %t failure=%t", got, system, err, tt.want, tt.system, tt.fails)
			}
		})
	}
}
