package stage

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// Server is a one-shot HTTPS payload server. It serves the payload exactly once
// then shuts itself down.
type Server struct {
	data   []byte
	port   int
	path   string
	served atomic.Bool
}

// NewServer creates a one-shot HTTPS server for the given payload.
func NewServer(data []byte, port int) *Server {
	pathBytes := make([]byte, 8)
	rand.Read(pathBytes) //nolint:errcheck
	return &Server{
		data: data,
		port: port,
		path: "/" + hex.EncodeToString(pathBytes),
	}
}

// ListenAndServe starts the HTTPS server and blocks until the payload has been
// served once (or an error occurs). Prints the full URL before blocking.
func (s *Server) ListenAndServe() error {
	cert, err := selfSignedCert()
	if err != nil {
		return fmt.Errorf("generating cert: %w", err)
	}

	srv := &http.Server{
		Addr: fmt.Sprintf(":%d", s.port),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	http.HandleFunc(s.path, func(w http.ResponseWriter, r *http.Request) {
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

	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ip, ok := a.(*net.IPNet); ok && !ip.IP.IsLoopback() && ip.IP.To4() != nil {
			fmt.Printf("[+] Payload URL: https://%s:%d%s\n", ip.IP, s.port, s.path)
		}
	}

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
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
