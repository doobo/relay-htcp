package admin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// At-rest encryption for the SQLite store.
//
// Settings (the saved config YAML and every credential inside it) are never
// written as plaintext. Two layers are involved:
//
//   - a 32-byte data key (DEK) generated on first use, stored in the settings
//     table wrapped by the master key;
//   - a 32-byte master key (KEK) that never enters the database: by default it
//     lives in a separate 0600 key file next to the database, and can instead
//     be supplied through the RELAY_HTCP_MASTER_KEY environment variable.
//
// Values are sealed with AES-256-GCM using the DEK, with the setting name as
// additional authenticated data so a ciphertext cannot be moved to another
// row. Someone who copies only the database therefore gets opaque blobs, not
// tunnel tokens.
const (
	// MasterKeyEnv carries a hex or base64 encoded 32-byte KEK. When set, the
	// key file is neither read nor created.
	MasterKeyEnv = "RELAY_HTCP_MASTER_KEY"

	keySize = 32

	// dekSettingKey is the settings row that holds the wrapped data key.
	dekSettingKey = "__data_key__"

	// settingCipherPrefix marks an encrypted settings value.
	settingCipherPrefix = "enc:v1:"
	// dekCipherPrefix marks the wrapped data key.
	dekCipherPrefix = "kek:v1:"

	dekAAD           = "relay-htcp/data-key/v1"
	settingAADPrefix = "relay-htcp/setting/v1:"
)

// loadOrCreateMasterKey returns the 32-byte KEK, preferring the environment
// variable and otherwise reading (or creating) the 0600 key file at path.
func loadOrCreateMasterKey(path string) ([]byte, error) {
	if env := strings.TrimSpace(os.Getenv(MasterKeyEnv)); env != "" {
		key, err := decodeKeyMaterial(env)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", MasterKeyEnv, err)
		}
		return key, nil
	}
	if path == "" {
		return nil, errors.New("master key file path is empty")
	}
	// The loop handles the race where another process creates the key file
	// between our read and our O_EXCL create.
	for attempt := 0; attempt < 2; attempt++ {
		data, err := os.ReadFile(path)
		if err == nil {
			key, derr := decodeKeyMaterial(string(data))
			if derr != nil {
				return nil, fmt.Errorf("key file %s: %w", path, derr)
			}
			_ = os.Chmod(path, 0o600)
			return key, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("read key file %s: %w", path, err)
		}

		key, err := randomBytes(keySize)
		if err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("create key file %s: %w", path, err)
		}
		_, werr := f.WriteString(hex.EncodeToString(key) + "\n")
		cerr := f.Close()
		if werr != nil || cerr != nil {
			_ = os.Remove(path)
			if werr == nil {
				werr = cerr
			}
			return nil, fmt.Errorf("write key file %s: %w", path, werr)
		}
		// Best effort: the file was created with 0600 already; this also
		// tightens a pre-existing file on platforms where the mode applies.
		_ = os.Chmod(path, 0o600)
		return key, nil
	}
	return nil, fmt.Errorf("key file %s: created concurrently but unreadable", path)
}

// decodeKeyMaterial accepts a 32-byte key encoded as hex (64 chars) or
// standard/raw base64.
func decodeKeyMaterial(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty key material")
	}
	if len(s) == hex.EncodedLen(keySize) {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == keySize {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) == keySize {
		return b, nil
	}
	return nil, errors.New("key must be 32 bytes hex or base64 encoded")
}

// randomBytes returns n cryptographically random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("random: %w", err)
	}
	return b, nil
}

// seal encrypts plaintext with key and aad using AES-256-GCM, returning
// base64(nonce || ciphertext).
func seal(key, plaintext []byte, aad string) (string, error) {
	aead, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	out := aead.Seal(nonce, nonce, plaintext, []byte(aad))
	return base64.StdEncoding.EncodeToString(out), nil
}

// unseal reverses seal.
func unseal(key []byte, token, aad string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("ciphertext too short")
	}
	plain, err := aead.Open(nil, raw[:ns], raw[ns:], []byte(aad))
	if err != nil {
		return nil, errors.New("authentication failed (wrong key or tampered data)")
	}
	return plain, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("key must be %d bytes", keySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// wrapDataKey seals the DEK with the KEK for storage in the settings table.
func wrapDataKey(kek, dek []byte) (string, error) {
	token, err := seal(kek, dek, dekAAD)
	if err != nil {
		return "", err
	}
	return dekCipherPrefix + token, nil
}

// unwrapDataKey recovers the DEK from its stored form.
func unwrapDataKey(kek []byte, stored string) ([]byte, error) {
	if !strings.HasPrefix(stored, dekCipherPrefix) {
		return nil, errors.New("unknown data key format")
	}
	dek, err := unseal(kek, strings.TrimPrefix(stored, dekCipherPrefix), dekAAD)
	if err != nil {
		return nil, err
	}
	if len(dek) != keySize {
		return nil, fmt.Errorf("data key must be %d bytes", keySize)
	}
	return dek, nil
}
