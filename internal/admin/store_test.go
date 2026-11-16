package admin

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	t.Setenv(MasterKeyEnv, "")
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

func TestMigrateIdempotent(t *testing.T) {
	s := openTestStore(t)
	if err := s.Migrate(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func TestUserCRUD(t *testing.T) {
	s := openTestStore(t)
	hash, err := HashPassword("secret123")
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.CreateUser("alice", hash, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "alice" || !u.Enabled || u.Role != RoleAdmin {
		t.Fatalf("user = %+v", u)
	}

	if _, err := s.CreateUser("alice", hash, RoleViewer); err == nil {
		t.Fatal("duplicate username accepted")
	}

	got, err := s.GetUserByName("alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != u.ID || !VerifyPassword("secret123", got.PasswordHash) {
		t.Fatalf("get by name = %+v", got)
	}
	if VerifyPassword("wrong", got.PasswordHash) {
		t.Fatal("wrong password verified")
	}

	if _, err := s.GetUserByName("nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}

	newHash, err := HashPassword("newpass")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUserPassword(u.ID, newHash); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUserRole(u.ID, RoleViewer); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUserEnabled(u.ID, false); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetUser(u.ID)
	if got.Role != RoleViewer || got.Enabled {
		t.Fatalf("after update = %+v", got)
	}

	users, err := s.ListUsers()
	if err != nil || len(users) != 1 {
		t.Fatalf("list = %d, %v", len(users), err)
	}

	if err := s.DeleteUser(u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetUser(u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}

func TestEnsureDefaultUser(t *testing.T) {
	s := openTestStore(t)
	h1, _ := HashPassword("first")
	created, err := s.EnsureDefaultUser("admin", h1)
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	h2, _ := HashPassword("second")
	created, err = s.EnsureDefaultUser("admin", h2)
	if err != nil || created {
		t.Fatalf("second call: created=%v err=%v", created, err)
	}
	u, _ := s.GetUserByName("admin")
	if !VerifyPassword("first", u.PasswordHash) {
		t.Fatal("seed password was overwritten")
	}
}

func TestSessions(t *testing.T) {
	s := openTestStore(t)
	h, _ := HashPassword("x")
	u, err := s.CreateUser("bob", h, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.CreateSession(SHA256Hex("tok-live"), u.ID, time.Minute.Milliseconds()); err != nil {
		t.Fatal(err)
	}
	se, err := s.GetSession(SHA256Hex("tok-live"))
	if err != nil || se.UserID != u.ID {
		t.Fatalf("session = %+v, %v", se, err)
	}

	if _, err := s.GetSession(SHA256Hex("unknown")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}

	if err := s.CreateSession(SHA256Hex("tok-expired"), u.ID, -time.Minute.Milliseconds()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(SHA256Hex("tok-expired")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired: %v", err)
	}
	if err := s.PurgeExpiredSessions(); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteSession(SHA256Hex("tok-live")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(SHA256Hex("tok-live")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after logout: %v", err)
	}

	if err := s.CreateSession(SHA256Hex("tok2"), u.ID, 60000); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSessionsForUser(u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(SHA256Hex("tok2")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after revoke: %v", err)
	}
}

func TestSettings(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.GetSetting("config"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := s.SetSetting("config", "a: 1\n"); err != nil {
		t.Fatal(err)
	}
	v, err := s.GetSetting("config")
	if err != nil || v != "a: 1\n" {
		t.Fatalf("get = %q, %v", v, err)
	}
	if err := s.SetSetting("config", "a: 2\n"); err != nil {
		t.Fatal(err)
	}
	v, _ = s.GetSetting("config")
	if v != "a: 2\n" {
		t.Fatalf("upsert = %q", v)
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewLoginRateLimiter(3, time.Minute)
	if !rl.Allow("1.1.1.1") {
		t.Fatal("first attempt blocked")
	}
	for i := 0; i < 3; i++ {
		rl.RecordFailure("1.1.1.1")
	}
	if rl.Allow("1.1.1.1") {
		t.Fatal("still allowed after limit failures")
	}
	if !rl.Allow("2.2.2.2") {
		t.Fatal("other IP affected")
	}
	rl.RecordSuccess("1.1.1.1")
	if !rl.Allow("1.1.1.1") {
		t.Fatal("not cleared after success")
	}
}

func TestCountEnabledAdmins(t *testing.T) {
	s := openTestStore(t)
	h, _ := HashPassword("x")
	if _, err := s.CreateUser("a1", h, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser("v1", h, RoleViewer); err != nil {
		t.Fatal(err)
	}
	n, err := s.CountEnabledAdmins()
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if err := s.UpdateUserEnabled(1, false); err != nil {
		t.Fatal(err)
	}
	n, _ = s.CountEnabledAdmins()
	if n != 0 {
		t.Fatalf("n=%d", n)
	}
}
