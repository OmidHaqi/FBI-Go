package routing

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
)

// ExecutionState is a lifecycle observation, not a packet-delivery claim.
type ExecutionState string

const (
	StatePlanned     ExecutionState = "PLANNED"
	StatePreparing   ExecutionState = "PREPARING"
	StateApplying    ExecutionState = "APPLYING"
	StateVerifying   ExecutionState = "VERIFYING"
	StateActive      ExecutionState = "ACTIVE"
	StateRollingBack ExecutionState = "ROLLING_BACK"
	StateRecovering  ExecutionState = "RECOVERING"
	StateFailed      ExecutionState = "FAILED"
	StateCleaned     ExecutionState = "CLEANED"
)

var ErrExecutionUnsupported = errors.New("network execution is unsupported outside an owned isolated test namespace")

// NetworkExecutor is intentionally not exposed through daemon IPC. Production
// host application has no implementation in this milestone.
type NetworkExecutor interface {
	Apply(M2Plan) error
	Verify() error
	Rollback() error
	State() ExecutionState
}

// DryRunExecutor reuses the M2 planner and cannot mutate any resource.
type DryRunExecutor struct{}

func (DryRunExecutor) Plan(in Inventory) M2Plan { return PlanM2(in) }
func (DryRunExecutor) Apply(M2Plan) error       { return ErrExecutionUnsupported }
func (DryRunExecutor) Verify() error            { return ErrExecutionUnsupported }
func (DryRunExecutor) Rollback() error          { return ErrExecutionUnsupported }
func (DryRunExecutor) State() ExecutionState    { return StatePlanned }

// IsolatedExecutor only wraps a rootless NamespaceEngine created by the
// dedicated launcher. It cannot open a client-supplied namespace or journal.
type IsolatedExecutor struct{ engine *NamespaceEngine }

func NewIsolatedExecutor(e *NamespaceEngine) (*IsolatedExecutor, error) {
	if e == nil || !e.rootless {
		return nil, ErrExecutionUnsupported
	}
	if err := verifyRootlessIsolation(); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.validate(); err != nil {
		return nil, err
	}
	j, err := loadJournal(e.journalPath)
	if err != nil {
		return nil, err
	}
	id, err := namespaceIdentity(filepath.Join("/run/netns", e.name))
	if err != nil {
		return nil, err
	}
	if j.Name != e.name || j.Identity != id || j.NFTTable != e.tableName || j.Phase != e.journalPhase {
		return nil, errors.New("isolated executor journal identity or phase mismatch")
	}
	return &IsolatedExecutor{engine: e}, nil
}

func (x *IsolatedExecutor) Apply(p M2Plan) error {
	if x == nil || x.engine == nil {
		return ErrExecutionUnsupported
	}
	if err := verifyRootlessIsolation(); err != nil {
		return err
	}
	return x.engine.Apply(p)
}

func (x *IsolatedExecutor) Verify() error {
	if x == nil || x.engine == nil {
		return ErrExecutionUnsupported
	}
	if err := verifyRootlessIsolation(); err != nil {
		return err
	}
	e := x.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.applied == nil || e.journalPhase != "active" {
		return errors.New("no active owned transaction")
	}
	j, err := loadJournal(e.journalPath)
	if err != nil {
		return err
	}
	if j.Plan == nil || j.Phase != "active" || j.NFTState != e.nftState || !reflect.DeepEqual(*j.Plan, *e.applied) {
		return errors.New("active journal differs from in-memory resources")
	}
	return e.verifyAppliedLocked(*e.applied)
}

func (x *IsolatedExecutor) Rollback() error {
	if x == nil || x.engine == nil {
		return ErrExecutionUnsupported
	}
	if err := verifyRootlessIsolation(); err != nil {
		return err
	}
	return x.engine.Disable()
}

func (x *IsolatedExecutor) State() ExecutionState {
	if x == nil || x.engine == nil {
		return StateFailed
	}
	e := x.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	switch e.journalPhase {
	case "created":
		if e.completed {
			return StateCleaned
		}
		return StatePlanned
	case "preparing":
		return StatePreparing
	case "applying":
		return StateApplying
	case "verifying":
		return StateVerifying
	case "active":
		return StateActive
	case "cleaning":
		return StateRollingBack
	default:
		return StateFailed
	}
}

// ReconcileIsolatedJournals accepts no caller path and runs only under the
// launcher's verified private /run/netns and journal directory.
func ReconcileIsolatedJournals() error {
	if err := verifyRootlessIsolation(); err != nil {
		return err
	}
	dir := os.Getenv("FBI_GO_JOURNAL_DIR")
	if dir == "" {
		return fmt.Errorf("rootless journal directory missing: %w", ErrExecutionUnsupported)
	}
	return RecoverRootlessJournals(dir)
}
