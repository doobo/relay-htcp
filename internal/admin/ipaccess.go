package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Runtime IP access control for the admin panel.
//
// Two lists are stored in the settings table (encrypted at rest like every
// other setting):
//
//   - whitelist non-empty: only addresses/CIDRs in it are allowed;
//   - blacklist: matching addresses are always denied;
//   - loopback (127.0.0.1 / ::1) is never filtered, so a bad rule can always
//     be repaired locally;
//   - both lists empty: allow everyone.
//
// The client address is resolved with Cloudflare Tunnel / cloudflared in mind:
// CF-Connecting-IP, then the first X-Forwarded-For entry, then X-Real-IP are
// honoured when the direct peer is loopback/link-local (a local proxy).
const IPAccessKey = "ip_access"

// IPAccessSettings is the persisted, human-editable form of the rules.
type IPAccessSettings struct {
	Whitelist []string `json:"whitelist"`
	Blacklist []string `json:"blacklist"`
}

// ipRules is the parsed, request-time form.
type ipRules struct {
	whitelist []netip.Prefix
	blacklist []netip.Prefix
	settings  IPAccessSettings
}

func parseIPAccess(in IPAccessSettings) (*ipRules, error) {
	wl, wlRaw, err := parseIPEntries(in.Whitelist)
	if err != nil {
		return nil, fmt.Errorf("whitelist: %w", err)
	}
	bl, blRaw, err := parseIPEntries(in.Blacklist)
	if err != nil {
		return nil, fmt.Errorf("blacklist: %w", err)
	}
	return &ipRules{
		whitelist: wl,
		blacklist: bl,
		settings:  IPAccessSettings{Whitelist: wlRaw, Blacklist: blRaw},
	}, nil
}

func parseIPEntries(entries []string) ([]netip.Prefix, []string, error) {
	prefixes := make([]netip.Prefix, 0, len(entries))
	raw := make([]string, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		var p netip.Prefix
		var err error
		if strings.Contains(entry, "/") {
			p, err = netip.ParsePrefix(entry)
		} else {
			var addr netip.Addr
			addr, err = netip.ParseAddr(entry)
			if err == nil {
				p = netip.PrefixFrom(addr, addr.BitLen())
			}
		}
		if err != nil {
			return nil, nil, fmt.Errorf("invalid IP or CIDR %q", entry)
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		prefixes = append(prefixes, p.Masked())
		raw = append(raw, entry)
	}
	return prefixes, raw, nil
}

// allows reports whether addr may use the panel.
func (r *ipRules) allows(addr netip.Addr) bool {
	if r == nil {
		return true
	}
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return true
	}
	for _, p := range r.blacklist {
		if p.Contains(addr) {
			return false
		}
	}
	if len(r.whitelist) > 0 {
		for _, p := range r.whitelist {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}
	return true
}

// requestIP resolves the effective client address, including cloudflared.
func requestIP(r *http.Request) netip.Addr {
	remote := parseRemoteAddr(r.RemoteAddr)
	if !remote.IsValid() {
		return netip.Addr{}
	}
	if !isTrustedProxy(remote) {
		return remote
	}
	if ip := parseIPHeader(r.Header.Get("CF-Connecting-IP")); ip.IsValid() {
		return ip
	}
	for _, part := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		if ip := parseIPHeader(part); ip.IsValid() {
			return ip
		}
	}
	if ip := parseIPHeader(r.Header.Get("X-Real-IP")); ip.IsValid() {
		return ip
	}
	return remote
}

func parseRemoteAddr(value string) netip.Addr {
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(value, "[]")
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func parseIPHeader(value string) netip.Addr {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// isTrustedProxy reports whether forwarding headers may be believed. A local
// cloudflared (or nginx) connects from loopback; link-local is also accepted.
// Private LAN peers are NOT trusted: otherwise any LAN client could spoof
// CF-Connecting-IP and bypass the allowlist.
func isTrustedProxy(addr netip.Addr) bool {
	return addr.IsLoopback() || addr.IsLinkLocalUnicast()
}

// ipAccess wraps h with the current runtime rules.
func (a *Server) ipAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rules := a.ipRules.Load()
		if rules != nil && !rules.allows(requestIP(r)) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// LoadIPAccess reads the saved rules. A missing row means "allow everyone".
func (s *Store) LoadIPAccess() (IPAccessSettings, error) {
	raw, err := s.GetSetting(IPAccessKey)
	if errors.Is(err, ErrNotFound) {
		return IPAccessSettings{}, nil
	}
	if err != nil {
		return IPAccessSettings{}, err
	}
	var out IPAccessSettings
	if strings.TrimSpace(raw) == "" {
		return out, nil
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return IPAccessSettings{}, err
	}
	return out, nil
}

// SaveIPAccess persists normalized rules.
func (s *Store) SaveIPAccess(v IPAccessSettings) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.SetSetting(IPAccessKey, string(b))
}

func (a *Server) handleGetIPAccess(w http.ResponseWriter, r *http.Request) {
	rules := a.ipRules.Load()
	settings := IPAccessSettings{}
	if rules != nil {
		settings = rules.settings
	}
	client := requestIP(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"whitelist": settings.Whitelist,
		"blacklist": settings.Blacklist,
		"client_ip": client.String(),
	})
}

func (a *Server) handlePutIPAccess(w http.ResponseWriter, r *http.Request) {
	var req IPAccessSettings
	if err := decodeJSON(r, 1<<20, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	rules, err := parseIPAccess(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.store.SaveIPAccess(rules.settings); err != nil {
		writeError(w, http.StatusInternalServerError, "save rules: "+err.Error())
		return
	}
	a.ipRules.Store(rules)
	a.log.Info("ip access rules updated",
		"whitelist", len(rules.whitelist), "blacklist", len(rules.blacklist))
	client := requestIP(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"whitelist": rules.settings.Whitelist,
		"blacklist": rules.settings.Blacklist,
		"client_ip": client.String(),
	})
}
