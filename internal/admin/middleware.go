package admin

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
)

// identity is the authenticated caller injected into the request context.
type identity struct {
	user  User
	token string // raw session token; empty for the static token
	via   string // "session" or "static"
}

type ctxKey int

const identityKey ctxKey = 0

func withIdentity(r *http.Request, id *identity) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), identityKey, id))
}

func identityFrom(r *http.Request) (*identity, bool) {
	id, ok := r.Context().Value(identityKey).(*identity)
	return id, ok
}

// staticTokenIdentity is the identity used when the configured bootstrap
// token authenticates a request (script access, no DB user).
func staticTokenIdentity() *identity {
	return &identity{
		user: User{ID: 0, Username: "token", Role: RoleAdmin, Enabled: true},
		via:  "static",
	}
}

// extractBearer pulls the token out of an Authorization header.
func extractBearer(h string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimPrefix(h, prefix)
}

// authMiddleware authenticates every request: either the static bootstrap
// token or a live DB session. Failures get a uniform 401.
func (a *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearer(r.Header.Get("Authorization"))
		if token != "" && a.opts.Token != "" &&
			subtle.ConstantTimeCompare([]byte(token), []byte(a.opts.Token)) == 1 {
			next.ServeHTTP(w, withIdentity(r, staticTokenIdentity()))
			return
		}
		se, err := a.store.GetSession(SHA256Hex(token))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		u, err := a.store.GetUser(se.UserID)
		if err != nil || !u.Enabled {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next.ServeHTTP(w, withIdentity(r, &identity{user: u, token: token, via: "session"}))
	})
}

// requireWrite rejects write operations from identities without write access
// (viewer role or disabled users).
func requireWrite(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, _ := identityFrom(r)
		if !id.user.CanWrite() {
			writeError(w, http.StatusForbidden, "viewer role cannot modify")
			return
		}
		h(w, r)
	}
}
