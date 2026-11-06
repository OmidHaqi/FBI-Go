package health

import "testing"

func TestHysteresis(t *testing.T) {
	th := Thresholds{OfflineFailures: 3, RecoverySuccesses: 2, DegradedFailureRate: .2}
	if got := Evaluate(Healthy, Metrics{Available: true, Samples: 3, ConsecutiveFailures: 3}, th); got != Offline {
		t.Fatal(got)
	}
	if got := Evaluate(Offline, Metrics{Available: true, Samples: 4, ConsecutiveSuccesses: 1}, th); got != Offline {
		t.Fatal(got)
	}
	if got := Evaluate(Offline, Metrics{Available: true, Samples: 5, ConsecutiveSuccesses: 2}, th); got != Healthy {
		t.Fatal(got)
	}
}
