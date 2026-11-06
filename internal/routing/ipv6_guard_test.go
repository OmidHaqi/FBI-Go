package routing

import (
	"strings"
	"testing"
)

func TestIPv6GuardExactSnapshot(t *testing.T) {
	const name, operation = "fbi_m2t_abcdef", "0123456789abcdef0123456789abcdef"
	state := `{"nftables":[{"metainfo":{"version":"1.1.6"}},` +
		`{"table":{"family":"ip6","name":"fbi_m2t_abcdef_v6","handle":1,"comment":"fbi-go-v6:` + operation + `"}},` +
		`{"chain":{"family":"ip6","table":"fbi_m2t_abcdef_v6","name":"output","handle":1,"type":"filter","hook":"output","prio":-150,"policy":"accept"}},` +
		`{"rule":{"family":"ip6","table":"fbi_m2t_abcdef_v6","chain":"output","handle":2,"expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"lo"}},{"accept":null}]}},` +
		`{"rule":{"family":"ip6","table":"fbi_m2t_abcdef_v6","chain":"output","handle":3,"expr":[{"counter":null},{"drop":null}]}}]}`
	if !validIPv6GuardSnapshot(name, operation, state) {
		t.Fatal("exact guard snapshot rejected")
	}
	for _, changed := range []string{
		strings.Replace(state, `"drop":null`, `"accept":null`, 1),
		strings.Replace(state, `"prio":-150`, `"prio":0`, 1),
		strings.Replace(state, `"fbi-go-v6:`+operation+`"`, `"foreign"`, 1),
		strings.Replace(state, `"counter":null`, `"counter":null},{"accept":null`, 1),
	} {
		if validIPv6GuardSnapshot(name, operation, changed) {
			t.Fatal("modified guard snapshot accepted")
		}
	}
}
