package routing

import (
	"github.com/omidhaqi/FBI-Go/internal/network"
	"strings"
	"testing"
)

func TestPlanSharedGateway(t *testing.T) {
	s := network.Snapshot{Devices: []network.Device{{Name: "a", Candidate: true, Gateways: []string{"192.0.2.1"}, Addresses: []string{"192.0.2.2/24"}}, {Name: "b", Candidate: true, Gateways: []string{"192.0.2.1"}, Addresses: []string{"192.0.2.3/24"}}}}
	p := Generate(s)
	if !p.ReadOnly || len(p.Candidates) != 2 {
		t.Fatal(p)
	}
	joined := strings.Join(p.Warnings, " ")
	if !strings.Contains(joined, "share gateway") || !strings.Contains(joined, "share subnet") {
		t.Fatal(joined)
	}
}
