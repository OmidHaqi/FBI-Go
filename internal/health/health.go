package health

import "math"

type State string

const (
	Healthy  State = "HEALTHY"
	Degraded State = "DEGRADED"
	Offline  State = "OFFLINE"
	Unknown  State = "UNKNOWN"
)

type Metrics struct {
	Available            bool
	Samples              int
	FailureRate          float64
	ConsecutiveFailures  int
	ConsecutiveSuccesses int
	RTTMillis            float64
}
type Thresholds struct {
	OfflineFailures     int
	RecoverySuccesses   int
	DegradedFailureRate float64
	DegradedRTTMillis   float64
}

// Evaluate is a pure state transition. Live per-WAN probes belong to a later milestone.
func Evaluate(previous State, m Metrics, t Thresholds) State {
	if !m.Available {
		return Offline
	}
	if m.Samples == 0 {
		return Unknown
	}
	if t.OfflineFailures < 1 {
		t.OfflineFailures = 3
	}
	if t.RecoverySuccesses < 1 {
		t.RecoverySuccesses = 2
	}
	if m.ConsecutiveFailures >= t.OfflineFailures {
		return Offline
	}
	if previous == Offline && m.ConsecutiveSuccesses < t.RecoverySuccesses {
		return Offline
	}
	if m.FailureRate >= t.DegradedFailureRate && t.DegradedFailureRate > 0 || m.RTTMillis >= t.DegradedRTTMillis && t.DegradedRTTMillis > 0 {
		return Degraded
	}
	return Healthy
}

// Monitor records bounded, per-WAN probe outcomes and applies Evaluate's
// failure/recovery hysteresis. The caller must route each probe through the
// intended WAN; Monitor itself never opens a socket or changes routing.
type Monitor struct {
	State      State
	Metrics    Metrics
	Thresholds Thresholds
}

func (m *Monitor) Observe(available, reached bool, rttMillis float64) State {
	m.Metrics.Available = available
	if available {
		m.Metrics.Samples++
		failure := 0.0
		if !reached {
			failure = 1
			m.Metrics.ConsecutiveFailures++
			m.Metrics.ConsecutiveSuccesses = 0
		} else {
			m.Metrics.ConsecutiveSuccesses++
			m.Metrics.ConsecutiveFailures = 0
			if rttMillis >= 0 && !math.IsNaN(rttMillis) && !math.IsInf(rttMillis, 0) {
				if m.Metrics.Samples == 1 {
					m.Metrics.RTTMillis = rttMillis
				} else {
					m.Metrics.RTTMillis = 0.75*m.Metrics.RTTMillis + 0.25*rttMillis
				}
			}
		}
		if m.Metrics.Samples == 1 {
			m.Metrics.FailureRate = failure
		} else {
			m.Metrics.FailureRate = 0.75*m.Metrics.FailureRate + 0.25*failure
		}
	} else {
		m.Metrics.ConsecutiveSuccesses = 0
		m.Metrics.ConsecutiveFailures++
	}
	m.State = Evaluate(m.State, m.Metrics, m.Thresholds)
	return m.State
}
