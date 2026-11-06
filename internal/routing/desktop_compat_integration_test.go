//go:build integration

package routing

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// This checks kernel namespace and shared-filesystem behavior only. It does
// not claim that a real Wayland, D-Bus, or DNS resolver session is compatible.
func TestRootlessDesktopCompatibility(t *testing.T) {
	if os.Getenv("FBI_GO_ROOTLESS_TEST") != "1" {
		t.Skip("requires dedicated rootless launcher")
	}
	if err := verifyRootlessIsolation(); err != nil {
		t.Fatalf("rootless isolation BLOCKED: %v", err)
	}
	service, err := NewRootlessTestNamespace()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := service.Close(); err != nil {
			t.Errorf("service namespace cleanup: %v", err)
		}
	}()
	app, err := NewRootlessTestNamespace()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := app.Close(); err != nil {
			t.Errorf("application namespace cleanup: %v", err)
		}
	}()
	labRun(t, service, "ip", "link", "set", "lo", "up")
	labRun(t, app, "ip", "link", "set", "lo", "up")
	dir := t.TempDir()
	readyService := filepath.Join(dir, "service.json")
	readyApp := filepath.Join(dir, "app.json")
	fileSocket := filepath.Join(dir, "session.sock")
	abstractName := fmt.Sprintf("fbi-compat-%d", os.Getpid())
	var servers []*exec.Cmd
	var sockets []string
	defer func() {
		for _, cmd := range servers {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		for _, path := range sockets {
			_ = os.Remove(path)
		}
	}()
	script, err := filepath.Abs("testdata/desktop_compat.py")
	if err != nil {
		t.Fatal(err)
	}
	type ports struct {
		TCP int `json:"tcp_port"`
		UDP int `json:"udp_port"`
	}
	start := func(ns *NamespaceEngine, ready, socketPath, abstract string) ports {
		cmd := exec.Command("nsenter", "--net=/proc/self/fd/3", "--", "python3", script, "server", ready, socketPath, abstract)
		cmd.ExtraFiles = []*os.File{ns.fd}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		servers = append(servers, cmd)
		sockets = append(sockets, socketPath)
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			data, err := os.ReadFile(ready)
			if err == nil {
				var p ports
				if err := json.Unmarshal(data, &p); err != nil {
					t.Fatal(err)
				}
				if p.TCP == 0 || p.UDP == 0 {
					t.Fatalf("invalid compatibility ports: %+v", p)
				}
				return p
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("compatibility server startup timeout in %s", ns.Name())
		return ports{}
	}
	servicePorts := start(service, readyService, fileSocket, abstractName)
	probe := func(kind, address string, port int, want bool) {
		args := []string{"--net=/proc/self/fd/3", "--", "python3", script, kind, address, fmt.Sprint(port)}
		cmd := exec.Command("nsenter", args...)
		cmd.ExtraFiles = []*os.File{app.fd}
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s probe: %v: %s", kind, err, output)
		}
		var result struct {
			Connected bool `json:"connected"`
		}
		if err := json.Unmarshal(output, &result); err != nil {
			t.Fatalf("%s probe JSON: %v: %s", kind, err, output)
		}
		if result.Connected != want {
			t.Errorf("%s %s:%d connected=%t want %t", kind, address, port, result.Connected, want)
		}
	}
	probe("tcp", "127.0.0.1", servicePorts.TCP, false)
	probe("udp", "127.0.0.53", servicePorts.UDP, false)
	probe("unix-file", fileSocket, 0, true)
	probe("unix-abstract", abstractName, 0, false)
	appPorts := start(app, readyApp, filepath.Join(dir, "app.sock"), abstractName+"-app")
	probe("tcp", "127.0.0.1", appPorts.TCP, true)
	probe("udp", "127.0.0.53", appPorts.UDP, true)
}
