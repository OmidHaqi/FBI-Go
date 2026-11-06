package routing

import (
	"errors"
	"testing"
)

func TestDryRunExecutorCannotMutate(t *testing.T) {
	var x NetworkExecutor = DryRunExecutor{}
	if x.State() != StatePlanned {
		t.Fatal("dry-run state is not PLANNED")
	}
	p := DryRunExecutor{}.Plan(Inventory{})
	if p.SafeToApply {
		t.Fatal("incomplete inventory marked applicable")
	}
	for _, err := range []error{x.Apply(p), x.Verify(), x.Rollback()} {
		if !errors.Is(err, ErrExecutionUnsupported) {
			t.Fatalf("dry-run mutation available: %v", err)
		}
	}
}

func TestIsolatedExecutorRefusesUnownedNamespace(t *testing.T) {
	if _, err := NewIsolatedExecutor(nil); !errors.Is(err, ErrExecutionUnsupported) {
		t.Fatalf("nil namespace accepted: %v", err)
	}
	if _, err := NewIsolatedExecutor(&NamespaceEngine{}); !errors.Is(err, ErrExecutionUnsupported) {
		t.Fatalf("unowned namespace accepted: %v", err)
	}
	var x *IsolatedExecutor
	if !errors.Is(x.Apply(M2Plan{}), ErrExecutionUnsupported) || !errors.Is(x.Verify(), ErrExecutionUnsupported) || !errors.Is(x.Rollback(), ErrExecutionUnsupported) {
		t.Fatal("nil executor accepted mutation")
	}
	if x.State() != StateFailed {
		t.Fatal("nil executor state is not FAILED")
	}
}
