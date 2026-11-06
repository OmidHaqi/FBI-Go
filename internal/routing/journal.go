package routing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

type ownershipJournal struct {
	Version         int     `json:"version"`
	Name            string  `json:"name"`
	Identity        string  `json:"identity"`
	NFTTable        string  `json:"nft_table"`
	Phase           string  `json:"phase"`
	Plan            *M2Plan `json:"plan,omitempty"`
	NFTState        string  `json:"nft_state,omitempty"`
	OperationID     string  `json:"operation_id,omitempty"`
	NFTScriptHash   string  `json:"nft_script_sha256,omitempty"`
	IPv6GuardIntent bool    `json:"ipv6_guard_intent,omitempty"`
	IPv6GuardState  string  `json:"ipv6_guard_state,omitempty"`
	IPv6GuardHash   string  `json:"ipv6_guard_sha256,omitempty"`
}

func scriptFingerprint(script string) string {
	sum := sha256.Sum256([]byte(script))
	return hex.EncodeToString(sum[:])
}

func nftTableComment(state string) string {
	var doc struct {
		NFTables []struct {
			Table *struct {
				Comment string `json:"comment"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if json.Unmarshal([]byte(state), &doc) != nil {
		return ""
	}
	for _, entry := range doc.NFTables {
		if entry.Table != nil {
			return entry.Table.Comment
		}
	}
	return ""
}

// classifyIncompleteNFT detects visible conflicts without treating a table
// comment or matching rule counts as proof of exact rule-expression ownership.
// Kernel handles and dynamic counters are not configuration identities.
func classifyIncompleteNFT(j ownershipJournal, observed string) string {
	if j.OperationID == "" || !json.Valid([]byte(observed)) {
		return "MANUAL_INTERVENTION_REQUIRED"
	}
	if nftTableComment(observed) != "fbi-go:"+j.OperationID {
		return "CONFLICT"
	}
	if j.Plan == nil {
		return "MANUAL_INTERVENTION_REQUIRED"
	}
	script, err := NFTScript(*j.Plan)
	if err != nil {
		return "MANUAL_INTERVENTION_REQUIRED"
	}
	var expected []string
	for _, line := range strings.Split(script, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "add" && fields[1] == "rule" {
			expected = append(expected, fields[4])
		}
	}
	var doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal([]byte(observed), &doc) != nil {
		return "MANUAL_INTERVENTION_REQUIRED"
	}
	var rules []string
	chains := map[string]bool{}
	tables := 0
	for _, entry := range doc.NFTables {
		if len(entry) != 1 {
			return "MANUAL_INTERVENTION_REQUIRED"
		}
		for kind, raw := range entry {
			switch kind {
			case "metainfo":
			case "table":
				var table struct{ Family, Name, Comment string }
				if json.Unmarshal(raw, &table) != nil || table.Family != "ip" || table.Name != j.NFTTable || table.Comment != "fbi-go:"+j.OperationID {
					return "CONFLICT"
				}
				tables++
			case "chain":
				var chain struct {
					Family, Table, Name, Type, Hook, Policy string
					Prio                                    int
				}
				if json.Unmarshal(raw, &chain) != nil || chain.Family != "ip" || chain.Table != j.NFTTable || chains[chain.Name] {
					return "CONFLICT"
				}
				if chain.Name == "output" && (chain.Type != "route" || chain.Hook != "output" || chain.Prio != -150 || chain.Policy != "accept") || chain.Name == "postrouting" && (chain.Type != "nat" || chain.Hook != "postrouting" || chain.Prio != 100 || chain.Policy != "accept") || chain.Name != "output" && chain.Name != "postrouting" {
					return "CONFLICT"
				}
				chains[chain.Name] = true
			case "rule":
				var rule struct{ Family, Table, Chain string }
				if json.Unmarshal(raw, &rule) != nil || rule.Family != "ip" || rule.Table != j.NFTTable {
					return "CONFLICT"
				}
				rules = append(rules, rule.Chain)
			default:
				// The intended script creates no named sets, maps or other objects.
				return "CONFLICT"
			}
		}
	}
	if tables != 1 || !chains["output"] || !chains["postrouting"] || len(chains) != 2 || len(rules) != len(expected) {
		return "CONFLICT"
	}
	for i := range rules {
		if rules[i] != expected[i] {
			return "CONFLICT"
		}
	}
	// A same-count edit to an expression or anonymous map cannot be proved
	// absent from this structural check. Keep fail-closed recovery.
	return "MANUAL_INTERVENTION_REQUIRED"
}

func checkedJournalDir(path string) error {
	if !filepath.IsAbs(path) || path == "/tmp" || path == "/run" {
		return errors.New("journal directory must be a dedicated absolute path")
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm() != 0700 || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("journal directory must be a real mode-0700 directory")
	}
	if st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return errors.New("journal directory has another owner")
	}
	return nil
}

func (e *NamespaceEngine) initJournal() error {
	dir := os.Getenv("FBI_GO_JOURNAL_DIR")
	if dir == "" {
		var err error
		dir, err = os.MkdirTemp("/tmp", "fbi-go-m2-journal-")
		if err != nil {
			return err
		}
		e.ownJournalDir = true
	}
	if err := checkedJournalDir(dir); err != nil {
		if e.ownJournalDir {
			_ = os.Remove(dir)
		}
		return err
	}
	e.journalPath = filepath.Join(dir, e.name+".json")
	return e.writeJournal("created", nil, "")
}

func (e *NamespaceEngine) writeJournal(phase string, plan *M2Plan, nftState string) error {
	if e.journalPath == "" {
		return errors.New("ownership journal unavailable")
	}
	if err := e.validate(); err != nil {
		return err
	}
	if err := checkedJournalDir(filepath.Dir(e.journalPath)); err != nil {
		return err
	}
	identity, err := namespaceIdentity(filepath.Join("/run/netns", e.name))
	if err != nil {
		return err
	}
	record := ownershipJournal{Version: 3, Name: e.name, Identity: identity, NFTTable: e.tableName, Phase: phase, Plan: plan, NFTState: nftState, OperationID: e.operationID, NFTScriptHash: e.nftScriptHash, IPv6GuardIntent: e.ipv6GuardIntent, IPv6GuardState: e.ipv6GuardState, IPv6GuardHash: e.ipv6GuardHash}
	b, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(e.journalPath), ".fbi-journal-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(append(b, '\n')); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if e.afterStage != nil && phase == "verifying" {
		e.afterStage("during-snapshot")
	}
	if err = os.Rename(tmp, e.journalPath); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(e.journalPath))
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return err
	}
	e.journalPhase = phase
	return nil
}

func loadJournal(path string) (ownershipJournal, error) {
	if err := checkedJournalDir(filepath.Dir(path)); err != nil {
		return ownershipJournal{}, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ownershipJournal{}, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return ownershipJournal{}, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 1<<20 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return ownershipJournal{}, errors.New("unsafe journal file")
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return ownershipJournal{}, err
	}
	var j ownershipJournal
	if err := json.Unmarshal(b, &j); err != nil {
		return j, err
	}
	parts := strings.Split(j.Name, "-")
	if (j.Version != 1 && j.Version != 2 && j.Version != 3) || len(parts) != 4 || parts[0] != "fbi" || parts[1] != "m2t" || filepath.Base(path) != j.Name+".json" || j.Identity == "" || j.NFTTable != "fbi_m2t_"+parts[3] {
		return j, errors.New("invalid journal identity")
	}
	if j.IPv6GuardState != "" && (!j.IPv6GuardIntent || !validIPv6GuardSnapshot(j.NFTTable, j.OperationID, j.IPv6GuardState)) || j.IPv6GuardIntent && (j.Version != 3 || j.Plan == nil || j.OperationID == "" || j.IPv6GuardHash != scriptFingerprint(ipv6GuardScript(j.NFTTable, j.OperationID))) || !j.IPv6GuardIntent && (j.IPv6GuardState != "" || j.IPv6GuardHash != "") {
		return j, errors.New("invalid IPv6 guard ownership record")
	}
	if j.Phase != "created" && j.Phase != "preparing" && j.Phase != "applying" && j.Phase != "verifying" && j.Phase != "active" && j.Phase != "cleaning" {
		return j, errors.New("invalid journal phase")
	}
	if j.Phase != "created" && (j.Plan == nil || validateNamespacePlan(*j.Plan, j.NFTTable) != nil) {
		return j, errors.New("invalid journal plan")
	}
	if j.Version >= 2 && j.Phase != "created" {
		id, err := hex.DecodeString(j.OperationID)
		if err != nil || len(id) != 16 || len(j.NFTScriptHash) != 64 {
			return j, errors.New("invalid journal operation identity")
		}
		if j.NFTState == "" {
			script, err := NFTScript(*j.Plan)
			if err != nil {
				return j, fmt.Errorf("invalid journal nftables plan: %w", err)
			}
			script = strings.Replace(script, "add table ip "+j.NFTTable+"\n", "add table ip "+j.NFTTable+" { comment \"fbi-go:"+j.OperationID+"\"; }\n", 1)
			if scriptFingerprint(script) != j.NFTScriptHash {
				return j, errors.New("journal nftables intent fingerprint mismatch")
			}
		}
		if j.NFTState != "" && nftTableComment(j.NFTState) != "fbi-go:"+j.OperationID {
			return j, errors.New("journal nftables snapshot token mismatch")
		}
	}
	return j, nil
}

// RecoverRootlessJournals operates only in the launcher's private /run/netns.
// It refuses mismatched identities and unknown resources instead of guessing.
func RecoverRootlessJournals(dir string) error {
	if err := verifyRootlessIsolation(); err != nil {
		return err
	}
	if dir == "" || dir != os.Getenv("FBI_GO_JOURNAL_DIR") {
		return errors.New("journal directory does not match launcher")
	}
	if err := checkedJournalDir(dir); err != nil {
		return err
	}
	lockDir, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer lockDir.Close()
	if err := syscall.Flock(int(lockDir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("RECOVERY_BUSY: another reconciliation holds the journal directory lock: %w", err)
	}
	defer syscall.Flock(int(lockDir.Fd()), syscall.LOCK_UN)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type pending struct {
		path   string
		record ownershipJournal
	}
	var owned []pending
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		j, err := loadJournal(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		namePath := filepath.Join("/run/netns", j.Name)
		id, err := namespaceIdentity(namePath)
		if err != nil || id != j.Identity {
			return fmt.Errorf("%s: namespace identity missing or changed", j.Name)
		}
		owned = append(owned, pending{path: path, record: j})
	}
	// A gateway namespace can own the far end of a client's veth. Remove
	// journaled routing resources before deleting any created-only peer.
	sort.SliceStable(owned, func(i, j int) bool { return owned[i].record.Plan != nil && owned[j].record.Plan == nil })
	for _, item := range owned {
		j, path := item.record, item.path
		namePath := filepath.Join("/run/netns", j.Name)
		fd, err := os.Open(namePath)
		if err != nil {
			return err
		}
		info, err := fd.Stat()
		if err != nil {
			_ = fd.Close()
			return err
		}
		if id, err := namespaceIdentity(namePath); err != nil || id != j.Identity {
			_ = fd.Close()
			return fmt.Errorf("%s: namespace identity changed during recovery", j.Name)
		}
		e := &NamespaceEngine{name: j.Name, tableName: j.NFTTable, fd: fd, identity: info, rootless: true, journalPath: path, journalPhase: j.Phase, nftState: j.NFTState, operationID: j.OperationID, nftScriptHash: j.NFTScriptHash, ipv6GuardIntent: j.IPv6GuardIntent, ipv6GuardState: j.IPv6GuardState, ipv6GuardHash: j.IPv6GuardHash}
		if j.Plan != nil {
			e.applied = j.Plan
		}
		if err := e.Close(); err != nil {
			return fmt.Errorf("recover %s: %w", j.Name, err)
		}
	}
	// SIGKILL during atomic replacement can strand a completed temporary
	// journal. Remove it only after all recorded resources are reconciled.
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".fbi-journal-") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return fmt.Errorf("unsafe orphan journal: %s", entry.Name())
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}
