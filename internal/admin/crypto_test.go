package admin

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSecretYAML = "auth:\n  token: super-secret-token-value\n"

func rawSetting(t *testing.T, s *Store, key string) string {
	t.Helper()
	var v string
	if err := s.Read().QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v); err != nil {
		t.Fatalf("raw read %q: %v", key, err)
	}
	return v
}

func TestSettingsEncryptedAtRest(t *testing.T) {
	s := openTestStore(t)
	if err := s.SetSetting("config", testSecretYAML); err != nil {
		t.Fatal(err)
	}
	raw := rawSetting(t, s, "config")
	if strings.Contains(raw, "super-secret-token-value") {
		t.Fatalf("secret stored in plaintext: %q", raw)
	}
	if !strings.HasPrefix(raw, settingCipherPrefix) {
		t.Fatalf("value not encrypted: %q", raw)
	}
	got, err := s.GetSetting("config")
	if err != nil || got != testSecretYAML {
		t.Fatalf("roundtrip = %q, %v", got, err)
	}
}

func TestDataKeyStoredWrapped(t *testing.T) {
	s := openTestStore(t)
	if err := s.SetSetting("config", testSecretYAML); err != nil {
		t.Fatal(err)
	}
	wrapped := rawSetting(t, s, dekSettingKey)
	if !strings.HasPrefix(wrapped, dekCipherPrefix) {
		t.Fatalf("data key not wrapped: %q", wrapped)
	}
	if _, err := unwrapDataKey(s.kek, wrapped); err != nil {
		t.Fatalf("unwrap with correct master key: %v", err)
	}
	wrong := make([]byte, keySize)
	if _, err := unwrapDataKey(wrong, wrapped); err == nil {
		t.Fatal("data key unwrapped with a wrong master key")
	}
}

func TestKeyFileCreatedAndReused(t *testing.T) {
	t.Setenv(MasterKeyEnv, "")
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "admin.db")
	keyPath := dbPath + ".key"

	s, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("config", testSecretYAML); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) != keySize {
		t.Fatalf("key file content invalid: %v len=%d", err, len(key))
	}

	// Reopening with the same key file must decrypt the saved value.
	s2, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s2.Migrate(); err != nil {
		t.Fatal(err)
	}
	got, err := s2.GetSetting("config")
	if err != nil || got != testSecretYAML {
		t.Fatalf("reopen roundtrip = %q, %v", got, err)
	}
}

func TestWrongMasterKeyRejected(t *testing.T) {
	t.Setenv(MasterKeyEnv, "")
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "admin.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("config", testSecretYAML); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	// Replace the key file with a different valid key.
	other := make([]byte, keySize)
	for i := range other {
		other[i] = byte(i + 1)
	}
	if err := os.WriteFile(dbPath+".key", []byte(hex.EncodeToString(other)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s2.Migrate(); err == nil {
		t.Fatal("migrate accepted a database encrypted with another key")
	}
}

func TestTamperedSettingRejected(t *testing.T) {
	s := openTestStore(t)
	if err := s.SetSetting("config", testSecretYAML); err != nil {
		t.Fatal(err)
	}
	raw := rawSetting(t, s, "config")
	body := strings.TrimPrefix(raw, settingCipherPrefix)
	// Flip one base64 character inside the ciphertext.
	last := body[len(body)-1]
	repl := byte('A')
	if last == 'A' {
		repl = 'B'
	}
	tampered := settingCipherPrefix + body[:len(body)-1] + string(repl)
	if _, err := s.Write().Exec(
		`UPDATE settings SET value = ? WHERE key = 'config'`, tampered); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSetting("config"); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

func TestLegacyPlaintextSettingsEncryptedOnMigrate(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Write().Exec(
		`INSERT INTO settings (key, value, updated_at) VALUES ('config', ?, 0)`,
		testSecretYAML); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	raw := rawSetting(t, s, "config")
	if !strings.HasPrefix(raw, settingCipherPrefix) {
		t.Fatalf("legacy value not encrypted: %q", raw)
	}
	got, err := s.GetSetting("config")
	if err != nil || got != testSecretYAML {
		t.Fatalf("legacy roundtrip = %q, %v", got, err)
	}
}

func TestDecodeKeyMaterial(t *testing.T) {
	want := make([]byte, keySize)
	for i := range want {
		want[i] = byte(i)
	}
	if _, err := decodeKeyMaterial(hex.EncodeToString(want)); err != nil {
		t.Fatalf("hex: %v", err)
	}
	if _, err := decodeKeyMaterial("short"); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestMasterKeyFromEnvironment(t *testing.T) {
	key := make([]byte, keySize)
	for i := range key {
		key[i] = byte(i + 7)
	}
	t.Setenv(MasterKeyEnv, hex.EncodeToString(key))

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "env.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("config", testSecretYAML); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err := os.Stat(dbPath + ".key"); !os.IsNotExist(err) {
		t.Fatalf("key file created despite environment key: %v", err)
	}

	s2, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s2.Migrate(); err != nil {
		t.Fatal(err)
	}
	if got, err := s2.GetSetting("config"); err != nil || got != testSecretYAML {
		t.Fatalf("env reopen = %q, %v", got, err)
	}
}
