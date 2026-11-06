package routing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestJournalRejectsTamperedOwnership(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := checkedJournalDir(dir); err != nil {
		st, _ := os.Lstat(dir)
		t.Fatalf("%v: mode=%v uid=%d euid=%d", err, st.Mode(), st.Sys().(*syscall.Stat_t).Uid, os.Geteuid())
	}
	name := "fbi-m2t-123-abcdef"
	path := filepath.Join(dir, name+".json")
	j := ownershipJournal{Version: 1, Name: name, Identity: "4:123", NFTTable: "fbi_m2t_abcdef", Phase: "created"}
	b, _ := json.Marshal(j)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadJournal(path); err != nil {
		t.Fatal(err)
	}
	j.Name = "fbi-m2t-foreign"
	b, _ = json.Marshal(j)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadJournal(path); err == nil {
		t.Fatal("mismatched journal name accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	if _, err := loadJournal(path); err == nil {
		t.Fatal("symlink journal accepted")
	}
}

func TestJournalRejectsCorruptRecord(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "fbi-m2t-123-abcdef.json")
	if err := os.WriteFile(path, []byte("{broken-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadJournal(path); err == nil {
		t.Fatal("corrupt journal accepted")
	}
}

func TestOwnedRouteCleanupClassification(t *testing.T) {
	w := Allocation{SourceCIDR: "192.0.2.9/24", SourceIP: "192.0.2.9", Gateway: "192.0.2.1", Interface: "fbi_ca"}
	if !ownedRouteLine(w, "unreachable default metric 4278198272") {
		t.Fatal("fail-closed route not recognized")
	}
	if ownedRouteLine(w, "unreachable default metric 1") {
		t.Fatal("foreign unreachable route accepted")
	}
	if ownedRouteLine(w, "default via 192.0.2.2 dev fbi_ca src 192.0.2.9") {
		t.Fatal("foreign gateway accepted")
	}
	if hasNFTTable("table ip fbi_m2t_abcdef_other\n", "fbi_m2t_abcdef") {
		t.Fatal("NFT prefix collision accepted")
	}
}

func TestPinnedTableHasUnreachableFallbackBeforeRule(t *testing.T) {
	w := Allocation{Table: 30001, Priority: 15001, Mark: 0x40000002, Interface: "fbi_cb", SourceCIDR: "198.51.100.99/24", SourceIP: "198.51.100.99", Gateway: "198.51.100.216"}
	steps := wanSteps(w)
	if len(steps) != 4 {
		t.Fatalf("unexpected route plan: %+v", steps)
	}
	if got := strings.Join(steps[1].add, " "); !strings.Contains(got, "unreachable default metric 4278198272") {
		t.Fatalf("missing fail-closed fallback: %s", got)
	}
	if got := strings.Join(steps[2].add, " "); !strings.Contains(got, "default via 198.51.100.216 dev fbi_cb") {
		t.Fatalf("missing preferred gateway: %s", got)
	}
	if got := strings.Join(steps[3].add, " "); !strings.Contains(got, "fwmark 0x40000002/0xffffffff lookup 30001") {
		t.Fatalf("mark does not select pinned table: %s", got)
	}
}

func TestNFTIntentFingerprintAndToken(t *testing.T) {
	script := "add table ip fbi_m2t_abcdef { comment \"fbi-go:0123456789abcdef0123456789abcdef\"; }\n"
	if scriptFingerprint(script) == scriptFingerprint(script+"add rule ip fbi_m2t_abcdef output accept\n") {
		t.Fatal("changed nftables intent retained its fingerprint")
	}
	state := `{"nftables":[{"metainfo":{"version":"1.1.6"}},{"table":{"family":"ip","name":"fbi_m2t_abcdef","handle":1,"comment":"fbi-go:0123456789abcdef0123456789abcdef"}}]}`
	if got := nftTableComment(state); got != "fbi-go:0123456789abcdef0123456789abcdef" {
		t.Fatalf("lost table ownership token: %q", got)
	}
	if nftTableComment(`{"nftables":[{"table":{"name":"foreign"}}]}`) != "" {
		t.Fatal("uncommented foreign table accepted")
	}
}

func TestIncompleteNFTClassificationNeverAuthorizesDeletion(t *testing.T) {
	p := M2Plan{SafeToApply: true, NFTTable: "fbi_m2t_abcdef", WANs: []Allocation{{Interface: "fbi_ca", SourceCIDR: "192.0.2.9/24", SourceIP: "192.0.2.9", Mark: 0x40000001, Weight: 1}}}
	script, err := NFTScript(p)
	if err != nil {
		t.Fatal(err)
	}
	id := "0123456789abcdef0123456789abcdef"
	j := ownershipJournal{OperationID: id, NFTTable: p.NFTTable, Plan: &p}
	entries := []map[string]any{{"table": map[string]any{"family": "ip", "name": p.NFTTable, "comment": "fbi-go:" + id}}, {"chain": map[string]any{"family": "ip", "table": p.NFTTable, "name": "output", "type": "route", "hook": "output", "prio": -150, "policy": "accept"}}}
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(line, "add rule ip "+p.NFTTable+" output ") {
			entries = append(entries, map[string]any{"rule": map[string]any{"family": "ip", "table": p.NFTTable, "chain": "output", "expr": []any{map[string]any{"accept": nil}}}})
		}
	}
	entries = append(entries, map[string]any{"chain": map[string]any{"family": "ip", "table": p.NFTTable, "name": "postrouting", "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}})
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(line, "add rule ip "+p.NFTTable+" postrouting ") {
			entries = append(entries, map[string]any{"rule": map[string]any{"family": "ip", "table": p.NFTTable, "chain": "postrouting", "expr": []any{map[string]any{"accept": nil}}}})
		}
	}
	marshal := func() string {
		b, err := json.Marshal(map[string]any{"nftables": entries})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if got := classifyIncompleteNFT(j, marshal()); got != "MANUAL_INTERVENTION_REQUIRED" {
		t.Fatalf("same-count expressions must remain ambiguous: %s", got)
	}
	if got := classifyIncompleteNFT(j, "not-json"); got != "MANUAL_INTERVENTION_REQUIRED" {
		t.Fatalf("unreadable nftables state must remain ambiguous: %s", got)
	}
	legacy := j
	legacy.OperationID = ""
	if got := classifyIncompleteNFT(legacy, marshal()); got != "MANUAL_INTERVENTION_REQUIRED" {
		t.Fatalf("missing operation identity must remain ambiguous: %s", got)
	}
	entries = append(entries, map[string]any{"rule": map[string]any{"family": "ip", "table": p.NFTTable, "chain": "output"}})
	if got := classifyIncompleteNFT(j, marshal()); got != "CONFLICT" {
		t.Fatalf("foreign rule addition not detected: %s", got)
	}
}
