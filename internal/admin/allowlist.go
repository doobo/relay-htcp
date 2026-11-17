package admin

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// IPAllowlist restricts admin requests to a set of CIDRs. It is used when the
// panel shares the public tunnel port, so the login page is not exposed to the
// whole internet.
type IPAllowlist struct {
	prefixes []netip.Prefix
}

// ParseIPAllowlist parses CIDR strings. An empty list returns (nil, nil), which
// means "no restriction".
func ParseIPAllowlist(cidrs []string) (*IPAllowlist, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	a := &IPAllowlist{prefixes: make([]netip.Prefix, 0, len(cidrs))}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", c, err)
		}
		a.prefixes = append(a.prefixes, p.Masked())
	}
	return a, nil
}

// Allows reports whether remoteAddr (host:port or bare host) is permitted.
func (a *IPAllowlist) Allows(remoteAddr string) bool {
	if a == nil {
		return true
	}
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	return a.allowsAddr(addr.Unmap())
}

func (a *IPAllowlist) allowsAddr(addr netip.Addr) bool {
	if a == nil {
		return true
	}
	for _, p := range a.prefixes {
		if p.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}

// Wrap returns a handler that rejects disallowed clients with 403.
func (a *IPAllowlist) Wrap(next http.Handler) http.Handler {
	if a == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := requestIP(r)
		if !ip.IsValid() || !a.allowsAddr(ip) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
