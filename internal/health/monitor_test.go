package health

import "testing"

func TestMonitorFailureAndRecovery(t *testing.T) {
	m := Monitor{State: Unknown, Thresholds: Thresholds{OfflineFailures: 2, RecoverySuccesses: 2}}
	for _, step := range []struct {
		available, reached bool
		want               State
	}{
		{true, true, Healthy},
		{true, false, Healthy},
		{true, false, Offline},
		{true, true, Offline},
		{true, true, Healthy},
		{false, false, Offline},
		{true, true, Offline},
		{true, true, Healthy},
	} {
		if got := m.Observe(step.available, step.reached, 1); got != step.want {
			t.Fatalf("after available=%t reached=%t: got %s want %s", step.available, step.reached, got, step.want)
		}
	}
	if m.Metrics.Samples != 7 || m.Metrics.FailureRate < 0 || m.Metrics.FailureRate > 1 {
		t.Fatalf("invalid smoothed metrics: %+v", m.Metrics)
	}
}
