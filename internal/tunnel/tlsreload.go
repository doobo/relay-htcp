package tunnel

import (
	"crypto/tls"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"
)

// certCheckInterval bounds how often an incoming handshake stats the
// certificate file for a replacement. SIGHUP reloads bypass the throttle.
const certCheckInterval = time.Minute

// certReloader serves the TLS key pair and picks up replacements without a
// restart. It never drops the last good certificate: a broken or half-written
// file is logged and ignored until the next successful load.
type certReloader struct {
	log *slog.Logger

	mu        sync.Mutex
	certFile  string
	keyFile   string
	cert      *tls.Certificate
	stamp     string    // "<size>-<mtime>" when cert was loaded
	checkedAt time.Time // last time the file was stat'ed
}

func newCertReloader(certFile, keyFile string, log *slog.Logger) *certReloader {
	return &certReloader{log: log, certFile: certFile, keyFile: keyFile}
}

// load re-reads the pair from the current paths, unconditionally. On failure
// the previously loaded certificate stays in use and the error is returned.
func (r *certReloader) load() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loadLocked()
}

func (r *certReloader) loadLocked() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.cert = &cert
	r.stamp = fileStamp(r.certFile)
	r.checkedAt = time.Now()
	return nil
}

// configure points the loader at a new pair of paths (used when a reload
// changed tls.cert / tls.key) and loads them. If the new paths fail to load,
// the old paths and certificate are kept so the listener keeps working.
func (r *certReloader) configure(certFile, keyFile string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if certFile == r.certFile && keyFile == r.keyFile {
		return r.loadLocked()
	}
	prevCert, prevKey := r.certFile, r.keyFile
	r.certFile, r.keyFile = certFile, keyFile
	if err := r.loadLocked(); err != nil {
		r.certFile, r.keyFile = prevCert, prevKey
		return err
	}
	return nil
}

// get implements tls.Config.GetCertificate. It re-reads the files when they
// changed on disk, at most once per certCheckInterval.
func (r *certReloader) get() (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert != nil && time.Since(r.checkedAt) < certCheckInterval {
		return r.cert, nil
	}
	if stamp := fileStamp(r.certFile); r.cert == nil || stamp != r.stamp {
		if err := r.loadLocked(); err != nil {
			// A half-written replacement must not take the listener down.
			// Throttle the next attempt and keep serving what we have.
			r.checkedAt = time.Now()
			if r.cert == nil {
				return nil, err
			}
			r.log.Warn("tls: certificate reload failed, keeping the loaded one",
				"cert", r.certFile, "key", r.keyFile, "err", err)
			return r.cert, nil
		}
	} else {
		r.checkedAt = time.Now()
	}
	return r.cert, nil
}

// fileStamp fingerprints a file by size and mtime. An unreadable path yields
// "" so the next successful load restores a usable stamp.
func fileStamp(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return strconv.FormatInt(st.Size(), 10) + "-" + strconv.FormatInt(st.ModTime().UnixNano(), 10)
}
