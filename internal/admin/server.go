package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ConfigKey is the settings key under which the saved config YAML lives.
const ConfigKey = "config"

// Options configures an admin server.
type Options struct {
	// Version is reported in /api/status.
	Version string
	// Token is an optional static bootstrap token for script access.
	Token string
	// SessionTTL is the login session lifetime (default 24h).
	SessionTTL time.Duration
	// RateLimit / RateWindow bound failed login attempts per client IP.
	RateLimit  int
	RateWindow time.Duration
	// Source is where the config came from at startup: "db" or "file".
	Source string
	// ConfigPath is the YAML file written back on save (optional).
	ConfigPath string
	// Path mounts the panel under a URL prefix (e.g. "/admin"). Empty or "/"
	// keeps the original root layout.
	Path string
	// Allowlist restricts panel access by client IP. nil allows everyone.
	// Shared-port deployments should always set it.
	Allowlist *IPAllowlist
	// Restart, when set, lets the panel restart the running process (used by
	// the tunnel client). It should return quickly: the handler acknowledges
	// the request and runs it asynchronously after a short delay.
	Restart func()
}

func (o *Options) finalize() {
	if o.SessionTTL <= 0 {
		o.SessionTTL = DefaultSessionTTL
	}
	if o.RateLimit <= 0 {
		o.RateLimit = 10
	}
	if o.RateWindow <= 0 {
		o.RateWindow = time.Minute
	}
	if o.Source == "" {
		o.Source = "file"
	}
}

// Server is the admin HTTP server: login, live status, config editing and
// user management, protected by session or static-token auth.
type Server struct {
	store      *Store
	provider   Provider
	opts       Options
	log        *slog.Logger
	limiter    *LoginRateLimiter
	ui         http.Handler
	allowlist  *IPAllowlist
	challenges *challengeStore
	ipRules    atomic.Pointer[ipRules]
	traffic    *TrafficStats
	started    time.Time
	// configMu serializes read-modify-write updates of the config YAML
	// (form saves and token CRUD).
	configMu sync.Mutex

	mu  sync.Mutex
	srv *http.Server
}

// NewServer builds an admin server on top of store, serving the role
// described by provider. ui may be nil (API only).
func NewServer(store *Store, provider Provider, opts Options, ui http.Handler, log *slog.Logger) *Server {
	opts.finalize()
	a := &Server{
		store:      store,
		provider:   provider,
		opts:       opts,
		log:        log,
		limiter:    NewLoginRateLimiter(opts.RateLimit, opts.RateWindow),
		ui:         ui,
		allowlist:  opts.Allowlist,
		challenges: newChallengeStore(),
		started:    time.Now(),
	}
	a.traffic = NewTrafficStats(store, log)
	if settings, err := store.LoadIPAccess(); err != nil {
		log.Warn("load ip access rules, using empty rules", "err", err)
	} else if rules, perr := parseIPAccess(settings); perr != nil {
		log.Warn("invalid saved ip access rules, using empty rules", "err", perr)
	} else {
		a.ipRules.Store(rules)
	}
	return a
}

// Store exposes the underlying store (used by main for seeding).
func (a *Server) Store() *Store { return a.store }

// Traffic exposes the shared traffic recorder. Both the admin API and the
// role provider (tunnel server/client) record into the same instance.
func (a *Server) Traffic() *TrafficStats { return a.traffic }

// Allowlist exposes the panel IP allowlist (nil means unrestricted).
func (a *Server) Allowlist() *IPAllowlist { return a.allowlist }

// Handler assembles the admin HTTP handler tree:
//
//	POST /api/auth/login      public
//	/api/...                  session / static-token auth
//	/                         embedded UI (if configured)
func (a *Server) Handler() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /api/auth/me", a.handleMe)
	api.HandleFunc("POST /api/auth/logout", a.handleLogout)
	api.HandleFunc("GET /api/status", a.handleStatus)
	api.HandleFunc("POST /api/restart", requireWrite(a.handleRestart))
	api.HandleFunc("GET /api/config", requireAdmin(a.handleGetConfig))
	api.HandleFunc("PUT /api/config", requireWrite(a.handlePutConfig))
	api.HandleFunc("GET /api/config/form", a.handleGetConfigForm)
	api.HandleFunc("PUT /api/config/form", requireWrite(a.handlePutConfigForm))
	api.HandleFunc("GET /api/tokens", a.handleListTokens)
	api.HandleFunc("GET /api/tokens/{index}/traffic", a.handleTokenTraffic)
	api.HandleFunc("POST /api/tokens", requireWrite(a.handleCreateToken))
	api.HandleFunc("PUT /api/tokens/{index}", requireWrite(a.handleUpdateToken))
	api.HandleFunc("DELETE /api/tokens/{index}", requireWrite(a.handleDeleteToken))
	api.HandleFunc("GET /api/traffic/daily", a.handleDailyTraffic)
	api.HandleFunc("GET /api/ip-access", a.handleGetIPAccess)
	api.HandleFunc("PUT /api/ip-access", requireWrite(a.handlePutIPAccess))
	api.HandleFunc("GET /api/users", a.handleListUsers)
	api.HandleFunc("POST /api/users", requireWrite(a.handleCreateUser))
	api.HandleFunc("PUT /api/users/{id}", requireWrite(a.handleUpdateUser))
	api.HandleFunc("DELETE /api/users/{id}", requireWrite(a.handleDeleteUser))

	root := http.NewServeMux()
	root.HandleFunc("POST /api/auth/challenge", a.handleChallenge)
	root.HandleFunc("GET /api/auth/challenge", a.handleChallenge)
	root.HandleFunc("POST /api/auth/login", a.handleLogin)
	root.Handle("/api/", a.authMiddleware(api))
	if a.ui != nil {
		root.Handle("/", a.ui)
	}

	var h http.Handler = root
	if prefix := panelPath(a.opts.Path); prefix != "/" {
		outer := http.NewServeMux()
		// /admin -> /admin/ so relative asset and API URLs resolve.
		outer.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
			u := *r.URL
			u.Path = prefix + "/"
			http.Redirect(w, r, u.RequestURI(), http.StatusTemporaryRedirect)
		})
		outer.Handle(prefix+"/", http.StripPrefix(prefix, root))
		// Standalone mode: the listener root is the panel's front page, so it
		// lands on the login view instead of a 404. In shared mode the tunnel
		// only forwards the prefix, so the decoy page still owns "/".
		outer.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			u := *r.URL
			u.Path = prefix + "/"
			http.Redirect(w, r, u.RequestURI(), http.StatusTemporaryRedirect)
		})
		h = outer
	}
	h = a.ipAccess(h)
	return a.allowlist.Wrap(h)
}

// panelPath normalizes the configured prefix. Empty or "/" means the panel is
// served at the root of its listener.
func panelPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	if p == "" {
		return "/"
	}
	return p
}

// Serve runs the admin server on ln until ctx is canceled, then shuts down
// gracefully.
func (a *Server) Serve(ctx context.Context, ln net.Listener) error {
	a.mu.Lock()
	if a.srv != nil {
		a.mu.Unlock()
		return errors.New("admin: already serving")
	}
	a.srv = &http.Server{
		Handler:           a.Handler(),
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		ErrorLog:          slog.NewLogLogger(a.log.Handler(), slog.LevelDebug),
	}
	srv := a.srv
	a.mu.Unlock()

	// Periodic daily-traffic flush. Start is idempotent, so a standalone
	// listener, a mounted handler in main and tests can all call it.
	a.traffic.Start(ctx)

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = a.store.PurgeExpiredSessions()
				a.limiter.Forget()
			}
		}
	}()

	a.log.Info("admin panel listening", "addr", ln.Addr().String())
	errCh := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := srv.Shutdown(shutCtx)
		cancel()
		if err != nil {
			a.log.Info("admin shutdown timed out, forcing close")
			_ = srv.Close()
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// Close force-closes the HTTP server.
func (a *Server) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.srv == nil {
		return nil
	}
	return a.srv.Close()
}

// --- JSON helpers -----------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, limit int64, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, limit)).Decode(v)
}

// --- auth -------------------------------------------------------------------

// loginRequest is the encrypted/box/plaintext login body (see logincrypto.go).
type loginRequest = loginPayload

type loginResponse struct {
	Token     string      `json:"token"`
	ExpiresAt int64       `json:"expires_at"`
	User      UserSummary `json:"user"`
}

// handleChallenge issues the public keys and a single-use nonce used by the
// browser to encrypt the login payload.
func (a *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	challenge, err := a.challenges.Issue()
	if err != nil {
		a.log.Warn("issue login challenge", "err", err)
		writeError(w, http.StatusServiceUnavailable, "challenge unavailable, try again")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, challenge)
}

func (a *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	addr := requestIP(r)
	ip := addr.String()
	if !addr.IsValid() {
		ip = r.RemoteAddr
	}
	if !a.limiter.Allow(ip) {
		writeError(w, http.StatusTooManyRequests, "too many failed attempts, try later")
		return
	}
	var req loginRequest
	if err := decodeJSON(r, 1<<16, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	creds, err := a.resolveLoginCredentials(&req)
	if err != nil {
		// A stale challenge, tampered payload or unknown nonce: ask the
		// browser to fetch a fresh one. Count it as a failed attempt.
		a.limiter.RecordFailure(ip)
		a.log.Warn("login payload rejected", "ip", ip, "err", err)
		writeError(w, http.StatusBadRequest, "登录凭证无效或已过期，请刷新页面后重试")
		return
	}
	u, err := a.store.GetUserByName(creds.Username)
	if err == nil && u.Enabled && VerifyPassword(creds.Password, u.PasswordHash) {
		token, terr := RandomToken()
		if terr != nil {
			writeError(w, http.StatusInternalServerError, "token generation failed")
			return
		}
		ttlMs := a.opts.SessionTTL.Milliseconds()
		if serr := a.store.CreateSession(SHA256Hex(token), u.ID, ttlMs); serr != nil {
			writeError(w, http.StatusInternalServerError, "create session: "+serr.Error())
			return
		}
		_ = a.store.UpdateLastLogin(u.ID)
		a.limiter.RecordSuccess(ip)
		a.log.Info("admin login", "user", u.Username, "ip", ip)
		writeJSON(w, http.StatusOK, loginResponse{Token: token, ExpiresAt: nowMs() + ttlMs, User: u.Summary()})
		return
	}
	// Uniform failure for unknown user, disabled user and wrong password:
	// prevents username enumeration.
	a.limiter.RecordFailure(ip)
	writeError(w, http.StatusUnauthorized, "invalid username or password")
}

func (a *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r)
	if id.via == "session" {
		_ = a.store.DeleteSession(SHA256Hex(id.token))
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	id, _ := identityFrom(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"username": id.user.Username,
		"role":     id.user.Role,
	})
}

// --- status -----------------------------------------------------------------

func (a *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := a.provider.Status()
	st.Version = a.opts.Version
	st.UptimeSec = int64(time.Since(a.started).Seconds())
	st.StartedAt = a.started.UnixMilli()
	writeJSON(w, http.StatusOK, st)
}

// handleRestart acknowledges a restart request and triggers it shortly after,
// so the HTTP response can be flushed before the process tears down.
func (a *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if a.opts.Restart == nil {
		writeError(w, http.StatusNotImplemented, "restart is not supported by this role")
		return
	}
	id, _ := identityFrom(r)
	a.log.Info("restart requested via admin panel", "user", id.user.Username)
	writeJSON(w, http.StatusOK, map[string]string{"status": "restarting"})
	go func() {
		time.Sleep(150 * time.Millisecond)
		a.opts.Restart()
	}()
}

// --- config -----------------------------------------------------------------

func (a *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"yaml":   a.provider.CurrentConfigYAML(),
		"source": a.opts.Source,
	})
}

type configRequest struct {
	YAML string `json:"yaml"`
}

func (a *Server) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	var req configRequest
	if err := decodeJSON(r, 1<<20, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.YAML) == "" {
		writeError(w, http.StatusBadRequest, "yaml is empty")
		return
	}
	if err := a.provider.ValidateConfigYAML(req.YAML); err != nil {
		writeError(w, http.StatusBadRequest, "config invalid: "+err.Error())
		return
	}
	report, err := a.provider.ApplyConfigYAML(req.YAML)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "apply failed: "+err.Error())
		return
	}
	canon := a.provider.CurrentConfigYAML()
	if err := a.storeConfig(canon); err != nil {
		writeError(w, http.StatusInternalServerError, "config applied but not persisted: "+err.Error())
		return
	}
	a.log.Info("config saved via admin panel",
		"applied", report.Applied, "restart_required", report.RestartRequired)
	writeJSON(w, http.StatusOK, report)
}

// handleGetConfigForm returns the structured editor schema and the current
// values. Secret fields are replaced with an empty string and never leave the
// server in cleartext.
func (a *Server) handleGetConfigForm(w http.ResponseWriter, r *http.Request) {
	form, err := buildConfigForm(a.provider)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	form.Role = a.provider.Role()
	form.Source = a.opts.Source
	writeJSON(w, http.StatusOK, form)
}

type configFormRequest struct {
	Values map[string]any `json:"values"`
}

// handlePutConfigForm merges the structured form into the live config. Empty
// secret values keep their stored value, so the browser never has to receive
// (or resubmit) a cleartext credential.
func (a *Server) handlePutConfigForm(w http.ResponseWriter, r *http.Request) {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	var req configFormRequest
	if err := decodeJSON(r, 1<<20, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	y, err := applyConfigForm(a.provider, req.Values)
	if err != nil {
		writeError(w, http.StatusBadRequest, "config invalid: "+err.Error())
		return
	}
	if err := a.provider.ValidateConfigYAML(y); err != nil {
		writeError(w, http.StatusBadRequest, "config invalid: "+err.Error())
		return
	}
	report, err := a.provider.ApplyConfigYAML(y)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "apply failed: "+err.Error())
		return
	}
	canon := a.provider.CurrentConfigYAML()
	if err := a.storeConfig(canon); err != nil {
		writeError(w, http.StatusInternalServerError, "config applied but not persisted: "+err.Error())
		return
	}
	a.log.Info("config saved via admin form",
		"applied", report.Applied, "restart_required", report.RestartRequired)
	writeJSON(w, http.StatusOK, report)
}

// storeConfig persists the canonical YAML and writes the config file back.
func (a *Server) storeConfig(canon string) error {
	if err := a.store.SetSetting(ConfigKey, canon); err != nil {
		a.log.Error("config applied in memory but not persisted", "err", err)
		return err
	}
	if a.opts.ConfigPath != "" {
		if err := os.WriteFile(a.opts.ConfigPath, []byte(canon), 0o600); err != nil {
			a.log.Warn("config file write-back failed", "path", a.opts.ConfigPath, "err", err)
		}
	}
	return nil
}

// --- users ------------------------------------------------------------------

func (a *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.store.ListUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sums := make([]UserSummary, 0, len(users))
	for _, u := range users {
		sums = append(sums, u.Summary())
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": sums})
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (a *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := decodeJSON(r, 1<<16, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" || len(username) > 64 {
		writeError(w, http.StatusBadRequest, "username must be 1-64 characters")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	role := Role(req.Role)
	if role == "" {
		role = RoleAdmin
	}
	if role != RoleAdmin && role != RoleViewer {
		writeError(w, http.StatusBadRequest, "role must be admin or viewer")
		return
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	u, err := a.store.CreateUser(username, hash, role)
	if err != nil {
		writeError(w, http.StatusConflict, "username already exists")
		return
	}
	a.log.Info("admin user created", "user", u.Username, "role", u.Role)
	writeJSON(w, http.StatusCreated, u.Summary())
}

type updateUserRequest struct {
	Password *string `json:"password,omitempty"`
	Role     *string `json:"role,omitempty"`
	Enabled  *bool   `json:"enabled,omitempty"`
}

func (a *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	u, err := a.store.GetUser(id)
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, "user not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var req updateUserRequest
	if err := decodeJSON(r, 1<<16, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if last, _ := a.store.CountEnabledAdmins(); u.Role == RoleAdmin && u.Enabled && last <= 1 {
		if req.Role != nil && Role(*req.Role) != RoleAdmin {
			writeError(w, http.StatusBadRequest, "cannot demote the last enabled admin")
			return
		}
		if req.Enabled != nil && !*req.Enabled {
			writeError(w, http.StatusBadRequest, "cannot disable the last enabled admin")
			return
		}
	}
	revoked := false
	if req.Password != nil {
		if len(*req.Password) < 8 {
			writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
			return
		}
		hash, err := HashPassword(*req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := a.store.UpdateUserPassword(id, hash); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		revoked = true
	}
	if req.Role != nil {
		role := Role(*req.Role)
		if role != RoleAdmin && role != RoleViewer {
			writeError(w, http.StatusBadRequest, "role must be admin or viewer")
			return
		}
		if err := a.store.UpdateUserRole(id, role); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if req.Enabled != nil {
		if err := a.store.UpdateUserEnabled(id, *req.Enabled); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !*req.Enabled {
			revoked = true
		}
	}
	if revoked {
		_ = a.store.DeleteSessionsForUser(id)
	}
	updated, err := a.store.GetUser(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated.Summary())
}

func (a *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	u, err := a.store.GetUser(id)
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, "user not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	idn, _ := identityFrom(r)
	if idn.user.ID == u.ID {
		writeError(w, http.StatusBadRequest, "cannot delete your own account")
		return
	}
	if u.Role == RoleAdmin && u.Enabled {
		if last, _ := a.store.CountEnabledAdmins(); last <= 1 {
			writeError(w, http.StatusBadRequest, "cannot delete the last enabled admin")
			return
		}
	}
	if err := a.store.DeleteUser(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.log.Info("admin user deleted", "user", u.Username)
	w.WriteHeader(http.StatusNoContent)
}
