package routing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateManagedResolver(t *testing.T) {
	for _, tc := range []struct {
		name, contents, errorText string
	}{
		{"valid-search", "nameserver 203.0.113.7\nsearch lab.test\noptions timeout:1 attempts:1\n", ""},
		{"host-stub", "nameserver 127.0.0.53\n", "host-stub"},
		{"ipv6-server", "nameserver 2001:db8::53\n", "invalid"},
		{"comment-only", "# nameserver 203.0.113.7\nsearch lab.test\n", "no safe nameserver"},
		{"unsupported-directive", "nameserver 203.0.113.7\ninclude /tmp/other\n", "unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "resolv.conf")
			if err := os.WriteFile(path, []byte(tc.contents), 0600); err != nil {
				t.Fatal(err)
			}
			fd, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer fd.Close()
			err = validateManagedResolver(fd)
			if tc.errorText == "" && err != nil {
				t.Fatal(err)
			}
			if tc.errorText != "" && (err == nil || !strings.Contains(err.Error(), tc.errorText)) {
				t.Fatalf("got %v, want %q", err, tc.errorText)
			}
		})
	}
}
