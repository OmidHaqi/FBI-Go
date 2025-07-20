package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func printHelp() {
	fmt.Print(`FBI-Go: ForceBindIP
Usage:
  fbi <IP_ADDRESS> <COMMAND> [ARGS...]

Example:
  fbi 192.168.1.100 curl example.com

Notes:
  - You must use an IP address that exists on one of your network interfaces
  - To see your available IP addresses, run: ip addr
  - Only IPv4 addresses are currently supported

Environment:
  LD_PRELOAD   Path to binder.so (set automatically)
  FORCE_BIND_IP IP address to force bind (set automatically)
`)
}

func main() {
	if len(os.Args) < 3 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		printHelp()
		os.Exit(1)
	}

	ip := os.Args[1]
	cmdName := os.Args[2]
	cmdArgs := os.Args[3:]

	// Assume binder.so is in the same directory as the loader
	exeDir, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	relPath := filepath.Join(filepath.Dir(exeDir), "binder.so")

	// Convert to absolute path to ensure LD_PRELOAD works correctly
	binderPath, err := filepath.Abs(relPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting absolute path: %v\n", err)
		os.Exit(1)
	}

	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Env = append(os.Environ(),
		"LD_PRELOAD="+binderPath,
		"FORCE_BIND_IP="+ip,
	)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running command: %v\n", err)
		os.Exit(1)
	}
}
