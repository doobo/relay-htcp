package admin

import (
	"database/sql"
	"errors"
	"fmt"
)

// Role classifies what an admin user may do.
type Role string

const (
	// RoleAdmin may read and write (config, users).
	RoleAdmin Role = "admin"
	// RoleViewer may only read status and config.
	RoleViewer Role = "viewer"
)

// ErrNotFound is returned when a user or session does not exist.
var ErrNotFound = errors.New("admin: not found")

// User is one admin account. PasswordHash is internal; the API only ever
// exposes UserSummary.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         Role
	Enabled      bool
	CreatedAt    int64
	UpdatedAt    int64
	LastLoginAt  int64 // 0 = never
}

// CanWrite reports whether the user may perform write operations.
func (u User) CanWrite() bool { return u.Role == RoleAdmin && u.Enabled }

// UserSummary is the API-safe projection of User.
type UserSummary struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Role        Role   `json:"role"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   int64  `json:"created_at"`
	LastLoginAt int64  `json:"last_login_at,omitempty"`
}

// Summary strips the password hash.
func (u User) Summary() UserSummary {
	return UserSummary{ID: u.ID, Username: u.Username, Role: u.Role, Enabled: u.Enabled,
		CreatedAt: u.CreatedAt, LastLoginAt: u.LastLoginAt}
}

const userColumns = "id, username, password_hash, role, enabled, created_at, updated_at, last_login_at"

type scanner interface{ Scan(dest ...any) error }

func scanUser(row scanner) (User, error) {
	var u User
	var role string
	var enabled int
	var last sql.NullInt64
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &role, &enabled,
		&u.CreatedAt, &u.UpdatedAt, &last); err != nil {
		return User{}, err
	}
	u.Role = Role(role)
	u.Enabled = enabled != 0
	if last.Valid {
		u.LastLoginAt = last.Int64
	}
	return u, nil
}

// CreateUser inserts a new admin user and returns it.
func (s *Store) CreateUser(username, passwordHash string, role Role) (User, error) {
	if role != RoleAdmin && role != RoleViewer {
		return User{}, fmt.Errorf("invalid role %q", role)
	}
	now := nowMs()
	res, err := s.Write().Exec(
		`INSERT INTO admin_users (username, password_hash, role, enabled, created_at, updated_at)
		 VALUES (?, ?, ?, 1, ?, ?)`,
		username, passwordHash, string(role), now, now)
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return User{}, err
	}
	return s.GetUser(id)
}

// GetUser returns one user by id.
func (s *Store) GetUser(id int64) (User, error) {
	u, err := scanUser(s.Read().QueryRow(
		`SELECT `+userColumns+` FROM admin_users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// GetUserByName returns one user by username.
func (s *Store) GetUserByName(username string) (User, error) {
	u, err := scanUser(s.Read().QueryRow(
		`SELECT `+userColumns+` FROM admin_users WHERE username = ?`, username))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// ListUsers returns all users, oldest first.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.Read().Query(`SELECT ` + userColumns + ` FROM admin_users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// UpdateUserPassword replaces the password hash and bumps updated_at.
func (s *Store) UpdateUserPassword(id int64, passwordHash string) error {
	_, err := s.Write().Exec(
		`UPDATE admin_users SET password_hash = ?, updated_at = ? WHERE id = ?`,
		passwordHash, nowMs(), id)
	return err
}

// UpdateUserRole changes the role and bumps updated_at.
func (s *Store) UpdateUserRole(id int64, role Role) error {
	if role != RoleAdmin && role != RoleViewer {
		return fmt.Errorf("invalid role %q", role)
	}
	_, err := s.Write().Exec(
		`UPDATE admin_users SET role = ?, updated_at = ? WHERE id = ?`,
		string(role), nowMs(), id)
	return err
}

// UpdateUserEnabled toggles the enabled flag.
func (s *Store) UpdateUserEnabled(id int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.Write().Exec(
		`UPDATE admin_users SET enabled = ?, updated_at = ? WHERE id = ?`,
		v, nowMs(), id)
	return err
}

// DeleteUser removes the user and, via FK cascade, their sessions.
func (s *Store) DeleteUser(id int64) error {
	_, err := s.Write().Exec(`DELETE FROM admin_users WHERE id = ?`, id)
	return err
}

// UpdateLastLogin stamps the successful-login time.
func (s *Store) UpdateLastLogin(id int64) error {
	_, err := s.Write().Exec(
		`UPDATE admin_users SET last_login_at = ? WHERE id = ?`, nowMs(), id)
	return err
}

// EnsureDefaultUser inserts the seed admin if no user with the name exists.
// It never overwrites an existing account. Returns true when it created the
// user.
func (s *Store) EnsureDefaultUser(username, passwordHash string) (bool, error) {
	res, err := s.Write().Exec(
		`INSERT INTO admin_users (username, password_hash, role, enabled, created_at, updated_at)
		 SELECT ?, ?, 'admin', 1, ?, ?
		 WHERE NOT EXISTS (SELECT 1 FROM admin_users WHERE username = ?)`,
		username, passwordHash, nowMs(), nowMs(), username)
	if err != nil {
		return false, fmt.Errorf("seed user: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// CountEnabledAdmins counts enabled users with the admin role.
func (s *Store) CountEnabledAdmins() (int, error) {
	var n int
	err := s.Read().QueryRow(
		`SELECT COUNT(*) FROM admin_users WHERE role = ? AND enabled = 1`,
		string(RoleAdmin)).Scan(&n)
	return n, err
}

// Session is one logged-in client. The raw token is never stored; only its
// SHA-256 hash is.
type Session struct {
	TokenHash string
	UserID    int64
	CreatedAt int64
	ExpiresAt int64
}

// CreateSession stores a session token hash for the user, expiring in ttl.
func (s *Store) CreateSession(tokenHash string, userID int64, ttlMs int64) error {
	now := nowMs()
	_, err := s.Write().Exec(
		`INSERT INTO admin_sessions (token_hash, user_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?) ON CONFLICT(token_hash) DO UPDATE SET
			user_id = excluded.user_id, created_at = excluded.created_at,
			expires_at = excluded.expires_at`,
		tokenHash, userID, now, now+ttlMs)
	return err
}

// GetSession returns a live session by token hash. ErrNotFound is returned
// for unknown or expired tokens.
func (s *Store) GetSession(tokenHash string) (Session, error) {
	var se Session
	err := s.Read().QueryRow(
		`SELECT token_hash, user_id, created_at, expires_at FROM admin_sessions
		 WHERE token_hash = ? AND expires_at > ?`,
		tokenHash, nowMs()).Scan(&se.TokenHash, &se.UserID, &se.CreatedAt, &se.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	return se, err
}

// DeleteSession removes one session (logout).
func (s *Store) DeleteSession(tokenHash string) error {
	_, err := s.Write().Exec(`DELETE FROM admin_sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// DeleteSessionsForUser revokes all of a user's sessions (password change,
// disable, delete).
func (s *Store) DeleteSessionsForUser(userID int64) error {
	_, err := s.Write().Exec(`DELETE FROM admin_sessions WHERE user_id = ?`, userID)
	return err
}

// PurgeExpiredSessions removes sessions past their expiry.
func (s *Store) PurgeExpiredSessions() error {
	_, err := s.Write().Exec(`DELETE FROM admin_sessions WHERE expires_at <= ?`, nowMs())
	return err
}

// GetSetting returns the value for key, decrypting it if it was stored
// encrypted. Rows written as plaintext by older versions are returned as-is.
func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.Read().QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return s.decryptSetting(key, v)
}

// SetSetting upserts the value for key. The value is encrypted before it is
// written; plaintext never reaches the database.
func (s *Store) SetSetting(key, value string) error {
	enc, err := s.encryptSetting(key, value)
	if err != nil {
		return err
	}
	_, err = s.Write().Exec(
		`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value,
			updated_at = excluded.updated_at`,
		key, enc, nowMs())
	return err
}

// DeleteSetting removes a setting key.
func (s *Store) DeleteSetting(key string) error {
	_, err := s.Write().Exec(`DELETE FROM settings WHERE key = ?`, key)
	return err
}
