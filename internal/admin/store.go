// Package admin implements the relay-htcp admin backend: a SQLite store for
// users, sessions and configuration, plus the HTTP API and the
// authentication middleware that protects it.
package admin

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the admin database handle. It owns two pools: a single-connection
// writer (SQLite has one writer at a time; WAL keeps readers unblocked) and a
// larger read-only pool. It also holds the master key and the unwrapped data
// key used to encrypt settings at rest.
type Store struct {
	write   *sql.DB
	read    *sql.DB
	path    string
	keyPath string
	kek     []byte

	dekMu sync.Mutex
	dek   []byte
}

// Open opens (creating if needed) the SQLite database at path with the
// relay-htcp pragma set. The master key is read from the RELAY_HTCP_MASTER_KEY
// environment variable when set, otherwise from "<path>.key".
func Open(path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	return openAt(abs, abs+".key")
}

// OpenWithKey is Open with an explicit master key file path. An empty keyPath
// means "<path>.key". The RELAY_HTCP_MASTER_KEY environment variable still
// takes precedence over the key file.
func OpenWithKey(path, keyPath string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	if keyPath == "" {
		keyPath = abs + ".key"
	}
	if kabs, err := filepath.Abs(keyPath); err == nil {
		keyPath = kabs
	}
	return openAt(abs, keyPath)
}

func openAt(abs, keyPath string) (*Store, error) {
	w, err := sql.Open("sqlite", dsn(abs, false))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", abs, err)
	}
	r, err := sql.Open("sqlite", dsn(abs, true))
	if err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("open %s (ro): %w", abs, err)
	}
	w.SetMaxOpenConns(1)
	r.SetMaxOpenConns(8)
	if err := w.Ping(); err != nil {
		_ = w.Close()
		_ = r.Close()
		return nil, fmt.Errorf("ping %s: %w", abs, err)
	}
	kek, err := loadOrCreateMasterKey(keyPath)
	if err != nil {
		_ = w.Close()
		_ = r.Close()
		return nil, fmt.Errorf("admin master key: %w", err)
	}
	// Best effort: keep the database readable only by its owner on POSIX.
	_ = os.Chmod(abs, 0o600)
	return &Store{write: w, read: r, path: abs, keyPath: keyPath, kek: kek}, nil
}

// dsn builds a file: URI with pragmas applied to every new connection.
func dsn(absPath string, readOnly bool) string {
	pragmas := []string{
		"busy_timeout(5000)",
		"mmap_size(268435456)",
		"cache_size(-8000)",
		"temp_store(MEMORY)",
	}
	if readOnly {
		pragmas = append(pragmas, "query_only(1)")
	} else {
		pragmas = append(pragmas,
			"synchronous(NORMAL)",
			"foreign_keys(ON)",
			"journal_mode(WAL)",
			"wal_autocheckpoint(1000)",
		)
	}
	q := "?_pragma=" + strings.Join(pragmas, "&_pragma=")
	return "file:" + url.PathEscape(filepath.ToSlash(absPath)) + q
}

// schema is the idempotent baseline schema, applied in a single transaction.
// All timestamps are epoch milliseconds.
const schema = `
CREATE TABLE IF NOT EXISTS admin_users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	role          TEXT NOT NULL DEFAULT 'admin',
	enabled       INTEGER NOT NULL DEFAULT 1,
	created_at    INTEGER NOT NULL,
	updated_at    INTEGER NOT NULL,
	last_login_at INTEGER
);

CREATE TABLE IF NOT EXISTS admin_sessions (
	token_hash TEXT PRIMARY KEY,
	user_id    INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_user ON admin_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at);

CREATE TABLE IF NOT EXISTS settings (
	key        TEXT PRIMARY KEY,
	value      TEXT NOT NULL,
	updated_at INTEGER NOT NULL
);
`

// Migrate applies the baseline schema. It is idempotent and safe to run on
// every start. It also provisions the data key and re-encrypts any settings
// row still stored as plaintext by an older version.
func (s *Store) Migrate() error {
	if err := s.Transaction(func(tx *sql.Tx) error {
		_, err := tx.Exec(schema)
		return err
	}); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if _, err := s.ensureDEK(); err != nil {
		return fmt.Errorf("migrate: init data key: %w", err)
	}
	if err := s.encryptLegacySettings(); err != nil {
		return fmt.Errorf("migrate: encrypt settings: %w", err)
	}
	return nil
}

// Transaction runs fn in a write transaction: commit on nil, rollback
// otherwise (a panic is re-raised after rollback).
func (s *Store) Transaction(fn func(tx *sql.Tx) error) error {
	tx, err := s.write.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if rec := recover(); rec != nil {
			_ = tx.Rollback()
			panic(rec)
		}
	}()
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Write returns the single-connection writer pool.
func (s *Store) Write() *sql.DB { return s.write }

// Read returns the read-only pool.
func (s *Store) Read() *sql.DB { return s.read }

// Path returns the absolute database file path.
func (s *Store) Path() string { return s.path }

// KeyPath returns the master key file path. It is not consulted when the key
// comes from RELAY_HTCP_MASTER_KEY.
func (s *Store) KeyPath() string { return s.keyPath }

// ensureDEK loads the wrapped data key from the settings table, creating it on
// first use. The caller must have run Migrate first (the table is created
// there).
func (s *Store) ensureDEK() ([]byte, error) {
	s.dekMu.Lock()
	defer s.dekMu.Unlock()
	if s.dek != nil {
		return s.dek, nil
	}
	var wrapped string
	err := s.read.QueryRow(`SELECT value FROM settings WHERE key = ?`, dekSettingKey).Scan(&wrapped)
	switch {
	case err == nil:
		dek, derr := unwrapDataKey(s.kek, wrapped)
		if derr != nil {
			return nil, fmt.Errorf("unwrap data key (wrong master key or corrupted database?): %w", derr)
		}
		s.dek = dek
		return dek, nil
	case errors.Is(err, sql.ErrNoRows):
		dek, gerr := randomBytes(keySize)
		if gerr != nil {
			return nil, gerr
		}
		w, werr := wrapDataKey(s.kek, dek)
		if werr != nil {
			return nil, werr
		}
		if _, ierr := s.write.Exec(
			`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)`,
			dekSettingKey, w, nowMs()); ierr != nil {
			return nil, fmt.Errorf("store data key: %w", ierr)
		}
		s.dek = dek
		return dek, nil
	default:
		return nil, err
	}
}

// encryptSetting seals a settings value. Already-encrypted values are left
// untouched so a value can never be double wrapped by accident.
func (s *Store) encryptSetting(key, plain string) (string, error) {
	if strings.HasPrefix(plain, settingCipherPrefix) {
		return plain, nil
	}
	dek, err := s.ensureDEK()
	if err != nil {
		return "", err
	}
	token, err := seal(dek, []byte(plain), settingAADPrefix+key)
	if err != nil {
		return "", fmt.Errorf("encrypt setting %q: %w", key, err)
	}
	return settingCipherPrefix + token, nil
}

// decryptSetting opens a settings value. Plaintext values written by older
// versions are returned unchanged.
func (s *Store) decryptSetting(key, stored string) (string, error) {
	if !strings.HasPrefix(stored, settingCipherPrefix) {
		return stored, nil
	}
	dek, err := s.ensureDEK()
	if err != nil {
		return "", err
	}
	plain, err := unseal(dek, strings.TrimPrefix(stored, settingCipherPrefix), settingAADPrefix+key)
	if err != nil {
		return "", fmt.Errorf("decrypt setting %q: %w", key, err)
	}
	return string(plain), nil
}

// encryptLegacySettings re-encrypts rows left in plaintext by an earlier
// version. It runs once per start and is a no-op on an already encrypted
// database.
func (s *Store) encryptLegacySettings() error {
	rows, err := s.read.Query(`SELECT key, value FROM settings WHERE key <> ?`, dekSettingKey)
	if err != nil {
		return err
	}
	type item struct{ key, value string }
	var legacy []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.key, &it.value); err != nil {
			_ = rows.Close()
			return err
		}
		if !strings.HasPrefix(it.value, settingCipherPrefix) {
			legacy = append(legacy, it)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, it := range legacy {
		enc, err := s.encryptSetting(it.key, it.value)
		if err != nil {
			return err
		}
		if _, err := s.write.Exec(
			`UPDATE settings SET value = ?, updated_at = ? WHERE key = ?`,
			enc, nowMs(), it.key); err != nil {
			return err
		}
	}
	return nil
}

// Close closes both pools and drops key material from memory.
func (s *Store) Close() error {
	s.dekMu.Lock()
	s.dek = nil
	s.dekMu.Unlock()
	s.kek = nil
	werr := s.write.Close()
	rerr := s.read.Close()
	if werr != nil {
		return werr
	}
	return rerr
}

func nowMs() int64 { return time.Now().UnixMilli() }
