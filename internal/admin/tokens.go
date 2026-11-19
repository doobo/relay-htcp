package admin

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Client token management for the server role.
//
// Tokens live in the config YAML (auth.tokens), not in their own table. This
// page nevertheless gets dedicated endpoints so the structured config form can
// stay focused on tunnel settings and the token list can offer richer
// per-token editing (route, enabled, one-time token reveal).

// clientTokenView is the API-safe projection of one auth.tokens entry. The
// token value itself is never returned, only a short hint.
type clientTokenView struct {
	Index     int      `json:"index"`
	Name      string   `json:"name"`
	Routes    []string `json:"routes,omitempty"`
	Enabled   bool     `json:"enabled"`
	TokenSet  bool     `json:"token_set"`
	TokenHint string   `json:"token_hint,omitempty"`
	// StatsKey is the non-secret identity used by the daily traffic table.
	StatsKey string `json:"-"`
	// Per-token traffic limits (MB, 0 = unlimited) and their runtime switch.
	LimitEnabled   bool  `json:"limit_enabled"`
	DailyLimitMB   int64 `json:"daily_limit_mb"`
	WeeklyLimitMB  int64 `json:"weekly_limit_mb"`
	MonthlyLimitMB int64 `json:"monthly_limit_mb"`
	Blocked        bool  `json:"blocked"`
}

type tokenListResponse struct {
	Tokens []clientTokenView `json:"tokens"`
	Routes []string          `json:"routes"`
}

type tokenSaveResponse struct {
	// Token is set only when a new secret was generated in this request. It
	// is shown to the operator once and never stored in the clear by the UI.
	Token  string            `json:"token,omitempty"`
	Tokens []clientTokenView `json:"tokens"`
	Routes []string          `json:"routes"`
	Report SaveReport        `json:"report"`
}

type tokenRequest struct {
	Name     string   `json:"name"`
	Routes   []string `json:"routes"`
	Route    string   `json:"route"` // legacy single-route form
	Token    string   `json:"token"`
	Enabled  *bool    `json:"enabled"`
	Generate bool     `json:"generate"`

	LimitEnabled   *bool  `json:"limit_enabled"`
	DailyLimitMB   *int64 `json:"daily_limit_mb"`
	WeeklyLimitMB  *int64 `json:"weekly_limit_mb"`
	MonthlyLimitMB *int64 `json:"monthly_limit_mb"`
}

// effectiveRoutes merges the multi-select field with the legacy single route.
func (r tokenRequest) effectiveRoutes() []string {
	routes := r.Routes
	if len(routes) == 0 && strings.TrimSpace(r.Route) != "" {
		routes = []string{r.Route}
	}
	return normalizeRouteList(routes)
}

func normalizeRouteList(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, r := range in {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

// configValidationError marks a token edit that made the config invalid, so the
// handler can answer 400 instead of 500.
type configValidationError struct{ err error }

func (e configValidationError) Error() string { return e.err.Error() }
func (e configValidationError) Unwrap() error { return e.err }

func (a *Server) requireServerRole(w http.ResponseWriter) bool {
	if a.provider.Role() != "server" {
		writeError(w, http.StatusBadRequest, "客户端 Token 仅适用于服务端")
		return false
	}
	return true
}

func (a *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	if !a.requireServerRole(w) {
		return
	}
	doc, err := parseConfigDoc(a.provider.CurrentConfigYAML())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, tokenListResponse{
		Tokens: a.tokenViews(doc),
		Routes: routeNames(doc),
	})
}

// tokenViews projects the config into API-safe token views and stamps the
// cached runtime quota state. It never reads the database.
func (a *Server) tokenViews(doc map[string]any) []clientTokenView {
	views := listTokenViews(doc)
	if p, ok := a.provider.(TokenBlockProvider); ok {
		for i := range views {
			views[i].Blocked = p.TokenBlocked(views[i].StatsKey)
		}
	}
	return views
}

func (a *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	if !a.requireServerRole(w) {
		return
	}
	var req tokenRequest
	if err := decodeJSON(r, 1<<16, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	a.configMu.Lock()
	defer a.configMu.Unlock()

	doc, err := parseConfigDoc(a.provider.CurrentConfigYAML())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rows := tokenRows(doc)
	secret := strings.TrimSpace(req.Token)
	generated := ""
	if secret == "" {
		secret, err = RandomToken()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		generated = secret
	}
	row := map[string]any{
		"name":    strings.TrimSpace(req.Name),
		"token":   secret,
		"enabled": enabledValue(req.Enabled, true),
	}
	if routes := req.effectiveRoutes(); len(routes) > 0 {
		row["routes"] = stringSliceAny(routes)
	}
	if err := applyTokenLimits(row, req, true); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rows = append(rows, row)
	assignPath(doc, "auth.tokens", rows)

	report, err := a.saveTokenDoc(doc)
	if err != nil {
		writeTokenSaveError(w, err)
		return
	}
	canon, _ := parseConfigDoc(a.provider.CurrentConfigYAML())
	writeJSON(w, http.StatusOK, tokenSaveResponse{
		Token: generated, Tokens: a.tokenViews(canon), Routes: routeNames(canon), Report: report,
	})
}

func (a *Server) handleUpdateToken(w http.ResponseWriter, r *http.Request) {
	if !a.requireServerRole(w) {
		return
	}
	index, err := strconv.Atoi(r.PathValue("index"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token index")
		return
	}
	var req tokenRequest
	if err := decodeJSON(r, 1<<16, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	a.configMu.Lock()
	defer a.configMu.Unlock()

	doc, err := parseConfigDoc(a.provider.CurrentConfigYAML())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rows := tokenRows(doc)
	if index < 0 || index >= len(rows) {
		writeError(w, http.StatusNotFound, "token not found")
		return
	}
	old, _ := rows[index].(map[string]any)
	row := map[string]any{}
	for k, v := range old {
		row[k] = v
	}
	if name := strings.TrimSpace(req.Name); name != "" {
		row["name"] = name
	}
	if routes := req.effectiveRoutes(); len(routes) > 0 {
		row["routes"] = stringSliceAny(routes)
	} else {
		delete(row, "routes")
	}
	if req.Enabled != nil {
		row["enabled"] = *req.Enabled
	}
	generated := ""
	switch {
	case req.Generate:
		secret, gerr := RandomToken()
		if gerr != nil {
			writeError(w, http.StatusInternalServerError, gerr.Error())
			return
		}
		row["token"] = secret
		generated = secret
	case strings.TrimSpace(req.Token) != "":
		row["token"] = strings.TrimSpace(req.Token)
		// otherwise keep the existing token
	}
	if err := applyTokenLimits(row, req, false); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rows[index] = row
	assignPath(doc, "auth.tokens", rows)

	report, err := a.saveTokenDoc(doc)
	if err != nil {
		writeTokenSaveError(w, err)
		return
	}
	canon, _ := parseConfigDoc(a.provider.CurrentConfigYAML())
	writeJSON(w, http.StatusOK, tokenSaveResponse{
		Token: generated, Tokens: a.tokenViews(canon), Routes: routeNames(canon), Report: report,
	})
}

func (a *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	if !a.requireServerRole(w) {
		return
	}
	index, err := strconv.Atoi(r.PathValue("index"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token index")
		return
	}
	a.configMu.Lock()
	defer a.configMu.Unlock()

	doc, err := parseConfigDoc(a.provider.CurrentConfigYAML())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rows := tokenRows(doc)
	if index < 0 || index >= len(rows) {
		writeError(w, http.StatusNotFound, "token not found")
		return
	}
	if len(rows) == 1 {
		writeError(w, http.StatusBadRequest, "至少保留一个客户端 Token")
		return
	}
	rows = append(rows[:index], rows[index+1:]...)
	assignPath(doc, "auth.tokens", rows)

	report, err := a.saveTokenDoc(doc)
	if err != nil {
		writeTokenSaveError(w, err)
		return
	}
	canon, _ := parseConfigDoc(a.provider.CurrentConfigYAML())
	writeJSON(w, http.StatusOK, tokenSaveResponse{
		Tokens: a.tokenViews(canon), Routes: routeNames(canon), Report: report,
	})
}

// saveTokenDoc validates, hot-applies and persists a mutated config document.
func (a *Server) saveTokenDoc(doc map[string]any) (SaveReport, error) {
	b, err := yaml.Marshal(doc)
	if err != nil {
		return SaveReport{}, fmt.Errorf("render config: %w", err)
	}
	if err := a.provider.ValidateConfigYAML(string(b)); err != nil {
		return SaveReport{}, configValidationError{err}
	}
	report, err := a.provider.ApplyConfigYAML(string(b))
	if err != nil {
		return SaveReport{}, err
	}
	if err := a.storeConfig(a.provider.CurrentConfigYAML()); err != nil {
		return report, err
	}
	return report, nil
}

func writeTokenSaveError(w http.ResponseWriter, err error) {
	var ve configValidationError
	if errors.As(err, &ve) {
		writeError(w, http.StatusBadRequest, "config invalid: "+ve.Error())
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}

func parseConfigDoc(y string) (map[string]any, error) {
	doc := map[string]any{}
	if strings.TrimSpace(y) == "" {
		return doc, nil
	}
	if err := yaml.Unmarshal([]byte(y), &doc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return doc, nil
}

func tokenRows(doc map[string]any) []any {
	if raw, ok := lookupPath(doc, "auth.tokens"); ok {
		if rows, ok := raw.([]any); ok {
			return rows
		}
	}
	return nil
}

func listTokenViews(doc map[string]any) []clientTokenView {
	rows := tokenRows(doc)
	out := make([]clientTokenView, 0, len(rows))
	for i, item := range rows {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		view := clientTokenView{Index: i, Enabled: true}
		view.Name = strings.TrimSpace(asString(row["name"]))
		if enabled, ok := row["enabled"].(bool); ok {
			view.Enabled = enabled
		}
		if limit, ok := row["limit_enabled"].(bool); ok {
			view.LimitEnabled = limit
		}
		view.DailyLimitMB = asInt64(row["daily_limit_mb"])
		view.WeeklyLimitMB = asInt64(row["weekly_limit_mb"])
		view.MonthlyLimitMB = asInt64(row["monthly_limit_mb"])
		switch routes := row["routes"].(type) {
		case []any:
			for _, r := range routes {
				if name := strings.TrimSpace(asString(r)); name != "" {
					view.Routes = append(view.Routes, name)
				}
			}
		case []string:
			view.Routes = append(view.Routes, routes...)
		case string:
			if name := strings.TrimSpace(routes); name != "" {
				view.Routes = append(view.Routes, name)
			}
		}
		if secret := asString(row["token"]); secret != "" {
			view.TokenSet = true
			view.StatsKey = TokenStatsKey(secret)
			if len(secret) > 4 {
				view.TokenHint = "…" + secret[len(secret)-4:]
			} else {
				view.TokenHint = "已设置"
			}
		}
		out = append(out, view)
	}
	return out
}

func routeNames(doc map[string]any) []string {
	raw, ok := lookupPath(doc, "routes")
	if !ok {
		return nil
	}
	rows, _ := raw.([]any)
	out := make([]string, 0, len(rows))
	for _, item := range rows {
		row, _ := item.(map[string]any)
		if name := strings.TrimSpace(asString(row["name"])); name != "" {
			out = append(out, name)
		}
	}
	return out
}

func stringSliceAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

func enabledValue(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// applyTokenLimits writes the optional quota fields into a config row. On
// create (create=true) explicit false/zero values can simply be omitted; on
// update only fields present in the request are touched so a partial API
// caller cannot silently clear existing limits.
func applyTokenLimits(row map[string]any, req tokenRequest, create bool) error {
	type limitField struct {
		key   string
		value *int64
		label string
	}
	enabled := req.LimitEnabled
	if enabled != nil {
		if *enabled {
			row["limit_enabled"] = true
		} else {
			delete(row, "limit_enabled")
		}
	} else if create {
		delete(row, "limit_enabled")
	}
	for _, f := range []limitField{
		{"daily_limit_mb", req.DailyLimitMB, "日流量上限"},
		{"weekly_limit_mb", req.WeeklyLimitMB, "周流量上限"},
		{"monthly_limit_mb", req.MonthlyLimitMB, "月流量上限"},
	} {
		if f.value == nil {
			continue
		}
		if *f.value < 0 {
			return &tokenLimitError{f.label + "不能为负数"}
		}
		if *f.value == 0 {
			delete(row, f.key)
			continue
		}
		row[f.key] = *f.value
	}
	return nil
}

type tokenLimitError struct{ msg string }

func (e *tokenLimitError) Error() string { return e.msg }

func asInt64(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int32:
		return int64(x)
	case int64:
		return x
	case uint:
		return int64(x)
	case uint64:
		return int64(x)
	case float64:
		return int64(x)
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n
	default:
		return 0
	}
}
