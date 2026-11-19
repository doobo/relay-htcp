package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"relay-htcp/internal/config"
)

// writeCertPair writes a self-signed certificate with the given CN into dir,
// overwriting any previous pair so reloads can be observed on the same paths.
func writeCertPair(t *testing.T, dir, cn string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func certCN(t *testing.T, c *tls.Certificate) string {
	t.Helper()
	if c == nil {
		t.Fatal("no certificate")
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

// TestCertReloaderPicksUpReplacement covers both reload triggers: an explicit
// reload (SIGHUP) and the per-handshake file check.
func TestCertReloaderPicksUpReplacement(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, "cert-one")

	r := newCertReloader(certFile, keyFile, testLogger())
	if err := r.load(); err != nil {
		t.Fatal(err)
	}
	if got := certCN(t, getCert(t, r)); got != "cert-one" {
		t.Fatalf("initial cert CN = %q", got)
	}

	writeCertPair(t, dir, "cert-two")
	if err := r.configure(certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	if got := certCN(t, getCert(t, r)); got != "cert-two" {
		t.Fatalf("after configure, cert CN = %q, want cert-two", got)
	}

	// Without any help the handshake path notices the replacement once the
	// check throttle expires.
	writeCertPair(t, dir, "cert-three")
	r.mu.Lock()
	r.checkedAt = time.Now().Add(-2 * certCheckInterval)
	r.mu.Unlock()
	if got := certCN(t, getCert(t, r)); got != "cert-three" {
		t.Fatalf("after file change, cert CN = %q, want cert-three", got)
	}
}

// TestCertReloaderKeepsOldCertOnBrokenFile makes sure a half-written or
// invalid replacement never takes the listener down.
func TestCertReloaderKeepsOldCertOnBrokenFile(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, "good-cert")

	r := newCertReloader(certFile, keyFile, testLogger())
	if err := r.load(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.load(); err == nil {
		t.Fatal("load of a broken file must fail")
	}

	// The handshake path throttles on a failed reload and keeps serving the
	// last good certificate instead of erroring.
	r.mu.Lock()
	r.checkedAt = time.Now().Add(-2 * certCheckInterval)
	r.mu.Unlock()
	cert, err := r.get()
	if err != nil {
		t.Fatalf("get after a broken replacement returned an error: %v", err)
	}
	if got := certCN(t, cert); got != "good-cert" {
		t.Fatalf("cert CN = %q, want good-cert", got)
	}
}

func getCert(t *testing.T, r *certReloader) *tls.Certificate {
	t.Helper()
	c, err := r.get()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestServerTLSCertificateReload replaces the key pair under a running TLS
// listener and checks that the new certificate is served on the same port
// without a restart.
func TestServerTLSCertificateReload(t *testing.T) {
	target, stopTarget := echoTarget(t)
	defer stopTarget()

	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, "cn-before")
	cfg := serverConfigFor(target)
	cfg.TLS = config.TLSConfig{Cert: certFile, Key: keyFile}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(cfg, testLogger())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.ServeListener(ctx, ln)
	defer func() {
		cancel()
		srv.Close()
		_ = ln.Close()
	}()
	waitForAddr(t, ln.Addr().String())

	if got := peerCertCN(t, ln.Addr().String()); got != "cn-before" {
		t.Fatalf("served CN = %q, want cn-before", got)
	}

	writeCertPair(t, dir, "cn-after")
	if _, err := srv.ApplyConfig(cfg); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	if got := peerCertCN(t, ln.Addr().String()); got != "cn-after" {
		t.Fatalf("served CN after reload = %q, want cn-after", got)
	}
}

func peerCertCN(t *testing.T, addr string) string {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("no peer certificate")
	}
	return certs[0].Subject.CommonName
}
