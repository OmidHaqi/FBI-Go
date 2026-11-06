package routing

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// The guard belongs to the same test-owned namespace and durable journal as
// the IPv4 M2 plan. It is never installed in a caller-supplied or host netns.
func ipv6GuardTable(name string) string { return name + "_v6" }

func ipv6GuardScript(name, operation string) string {
	table := ipv6GuardTable(name)
	return fmt.Sprintf("add table ip6 %s { comment \"fbi-go-v6:%s\"; }\n"+
		"add chain ip6 %s output { type filter hook output priority -150; policy accept; }\n"+
		"add rule ip6 %s output oifname \"lo\" accept\n"+
		"add rule ip6 %s output counter drop\n", table, operation, table, table, table)
}

func validIPv6GuardSnapshot(name, operation, state string) bool {
	var doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal([]byte(state), &doc) != nil || len(doc.NFTables) != 5 {
		return false
	}
	table := ipv6GuardTable(name)
	want := []string{
		`{"table":{"family":"ip6","name":"` + table + `","comment":"fbi-go-v6:` + operation + `"}}`,
		`{"chain":{"family":"ip6","table":"` + table + `","name":"output","type":"filter","hook":"output","prio":-150,"policy":"accept"}}`,
		`{"rule":{"family":"ip6","table":"` + table + `","chain":"output","expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"lo"}},{"accept":null}]}}`,
		`{"rule":{"family":"ip6","table":"` + table + `","chain":"output","expr":[{"counter":null},{"drop":null}]}}`,
	}
	index := 0
	for _, object := range doc.NFTables {
		if _, metadata := object["metainfo"]; metadata {
			if len(object) != 1 {
				return false
			}
			continue
		}
		if index >= len(want) || len(object) != 1 {
			return false
		}
		for key, raw := range object {
			var observed map[string]any
			if json.Unmarshal(raw, &observed) != nil {
				return false
			}
			delete(observed, "handle") // kernel allocation, not configuration
			var expected map[string]json.RawMessage
			if json.Unmarshal([]byte(want[index]), &expected) != nil {
				return false
			}
			var value map[string]any
			if json.Unmarshal(expected[key], &value) != nil || !reflect.DeepEqual(observed, value) {
				return false
			}
		}
		index++
	}
	return index == 4
}

func (e *NamespaceEngine) currentIPv6Guard() (string, bool, error) {
	tables, err := e.run("", "nft", "list", "tables")
	if err != nil {
		return "", false, err
	}
	want := "table ip6 " + ipv6GuardTable(e.tableName)
	found := false
	for _, line := range strings.Split(tables, "\n") {
		if strings.TrimSpace(line) == want {
			found = true
		}
	}
	if !found {
		return "", false, nil
	}
	state, err := e.run("", "nft", "-j", "-s", "list", "table", "ip6", ipv6GuardTable(e.tableName))
	return state, true, err
}

// InstallIPv6Guard persists intent before the atomic nftables batch. A crash
// after the batch but before snapshot persistence requires manual recovery.
func (e *NamespaceEngine) InstallIPv6Guard() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.validate(); err != nil {
		return err
	}
	if e.applied == nil || e.journalPhase != "active" {
		return errors.New("active owned IPv4 plan required before IPv6 guard")
	}
	state, present, err := e.currentIPv6Guard()
	if err != nil {
		return err
	}
	if e.ipv6GuardIntent {
		if e.ipv6GuardState == "" {
			return errors.New("MANUAL_INTERVENTION_REQUIRED: IPv6 guard snapshot missing")
		}
		if !present || state != e.ipv6GuardState {
			return errors.New("CONFLICT: IPv6 guard changed")
		}
		return nil
	}
	if present {
		return errors.New("CONFLICT: IPv6 guard table name already occupied")
	}
	e.ipv6GuardIntent = true
	e.ipv6GuardHash = scriptFingerprint(ipv6GuardScript(e.tableName, e.operationID))
	if err := e.writeJournal("active", e.applied, e.nftState); err != nil {
		e.ipv6GuardIntent = false
		e.ipv6GuardHash = ""
		return err
	}
	if e.afterStage != nil {
		e.afterStage("ipv6-after-intent")
	}
	if _, err := e.run(ipv6GuardScript(e.tableName, e.operationID), "nft", "-f", "-"); err != nil {
		return fmt.Errorf("IPv6 guard nft batch: %w", err)
	}
	if e.afterStage != nil {
		e.afterStage("ipv6-after-batch")
		e.afterStage("ipv6-before-snapshot")
	}
	state, present, err = e.currentIPv6Guard()
	if err != nil || !present || !validIPv6GuardSnapshot(e.tableName, e.operationID, state) {
		return errors.New("MANUAL_INTERVENTION_REQUIRED: IPv6 guard installed but exact snapshot unavailable")
	}
	e.ipv6GuardState = state
	if err := e.writeJournal("active", e.applied, e.nftState); err != nil {
		return fmt.Errorf("persist IPv6 guard snapshot: %w", err)
	}
	if e.afterStage != nil {
		e.afterStage("ipv6-after-snapshot")
	}
	return nil
}

// VerifyIPv6Guard requires a durable exact snapshot and the same observed
// kernel structure. It is called by the internal executor before launch.
func (e *NamespaceEngine) VerifyIPv6Guard() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.validate(); err != nil {
		return err
	}
	if !e.ipv6GuardIntent || e.ipv6GuardState == "" {
		return errors.New("IPv6 guard has no durable verified snapshot")
	}
	state, present, err := e.currentIPv6Guard()
	if err != nil {
		return err
	}
	if !present || state != e.ipv6GuardState || !validIPv6GuardSnapshot(e.tableName, e.operationID, state) {
		return errors.New("CONFLICT: IPv6 guard differs from durable snapshot")
	}
	return nil
}

func (e *NamespaceEngine) disableIPv6GuardLocked() error {
	if !e.ipv6GuardIntent {
		return nil
	}
	state, present, err := e.currentIPv6Guard()
	if err != nil {
		return err
	}
	if present {
		if e.ipv6GuardState == "" {
			if e.ipv6GuardHash != scriptFingerprint(ipv6GuardScript(e.tableName, e.operationID)) || !validIPv6GuardSnapshot(e.tableName, e.operationID, state) {
				return errors.New("MANUAL_INTERVENTION_REQUIRED: IPv6 guard has no durable snapshot and differs from exact intent")
			}
		}
		if e.ipv6GuardState != "" && state != e.ipv6GuardState {
			return errors.New("CONFLICT: IPv6 guard differs from durable snapshot")
		}
	}
	if err := e.writeJournal("cleaning", e.applied, e.nftState); err != nil {
		return err
	}
	if present {
		if _, err := e.run("", "nft", "delete", "table", "ip6", ipv6GuardTable(e.tableName)); err != nil {
			return err
		}
	}
	e.ipv6GuardIntent, e.ipv6GuardState, e.ipv6GuardHash = false, "", ""
	return e.writeJournal("cleaning", e.applied, e.nftState)
}
