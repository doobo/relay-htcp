package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"sort"

	"relay-htcp/internal/config"
)

// Exposed stcp routes.
//
// A stcp route with bind set gets a listener on the server itself. Each
// accepted TCP connection is a visitor: it is paired with a provider client
// exactly like a visitor stream from a client, so the service behind the
// provider is reachable from the server's bind address.
//
// Provider choice is per source IP. Every enabled token that may use the route
// is ranked by a hash of (client IP, token), highest first, so the same IP
// keeps reaching the same client while that client is online. If it is
// offline, the next-ranked online client takes over.

// stcpExposure is one running server-side listener for an stcp route.
type stcpExposure struct {
	bind string
	ln   net.Listener
}

// startSTCPExposure binds the configured exposed routes for the lifetime of
// ctx. Listeners are closed when ctx ends.
func (s *Server) startSTCPExposure(ctx context.Context) {
	s.stcpMu.Lock()
	s.exposeCtx = ctx
	s.stcpMu.Unlock()
	s.syncSTCPExposure()
	go func() {
		<-ctx.Done()
		s.stopSTCPExposure()
	}()
}

// syncSTCPExposure reconciles the running listeners with the current
// configuration. It is called at startup and after every config apply, so
// adding, removing or moving a bind address takes effect without a restart.
// A bind that cannot be listened on is logged and skipped; it does not stop
// the tunnel server.
func (s *Server) syncSTCPExposure() {
	s.stcpMu.Lock()
	defer s.stcpMu.Unlock()
	if s.exposeCtx == nil {
		return
	}
	if s.exposed == nil {
		s.exposed = make(map[string]*stcpExposure)
	}
	desired := make(map[string]string)
	for _, r := range s.cfgGet().Routes {
		if r.Type == config.RouteTypeSTCP && r.Bind != "" {
			desired[r.Name] = r.Bind
		}
	}
	for route, ex := range s.exposed {
		if desired[route] != ex.bind {
			_ = ex.ln.Close()
			delete(s.exposed, route)
			s.log.Info("stcp route exposure stopped", "route", route, "bind", ex.bind)
		}
	}
	for route, bind := range desired {
		if _, ok := s.exposed[route]; ok {
			continue
		}
		ln, err := net.Listen("tcp", bind)
		if err != nil {
			s.log.Error("stcp route exposure failed", "route", route, "bind", bind, "err", err)
			continue
		}
		s.exposed[route] = &stcpExposure{bind: bind, ln: ln}
		s.log.Info("stcp route exposed", "route", route, "bind", ln.Addr().String())
		go s.acceptExposed(s.exposeCtx, route, ln)
	}
}

// stopSTCPExposure closes every exposed listener.
func (s *Server) stopSTCPExposure() {
	s.stcpMu.Lock()
	defer s.stcpMu.Unlock()
	for route, ex := range s.exposed {
		_ = ex.ln.Close()
		delete(s.exposed, route)
	}
}

// acceptExposed serves one exposed listener until it is closed.
func (s *Server) acceptExposed(ctx context.Context, route string, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go s.serveExposed(ctx, route, conn)
	}
}

// serveExposed pairs one visitor connection with the best online provider and
// relays bytes between them until either side closes.
func (s *Server) serveExposed(ctx context.Context, route string, conn net.Conn) {
	ranked := s.rankProviders(route, remoteHost(conn.RemoteAddr()))
	if len(ranked) == 0 {
		s.log.Warn("exposed stcp route has no provider", "route", route, "remote", conn.RemoteAddr().String())
		_ = conn.Close()
		return
	}
	peer, err := s.stcp.pairExposed(ctx, route, ranked, s.cfgGet().Tunnel.STCPTimeout)
	if err != nil {
		s.log.Debug("exposed stcp visitor found no provider", "route", route, "remote", conn.RemoteAddr().String(), "err", err)
		_ = conn.Close()
		return
	}
	relayConns(conn, peer)
}

// rankProviders returns the stats keys of the tokens allowed on route, ordered
// by a hash of (ip, token), highest first. Quota-blocked tokens are left out.
func (s *Server) rankProviders(route, ip string) []string {
	set := s.tokens.Load()
	if set == nil {
		return nil
	}
	type candidate struct {
		id    string
		score uint64
	}
	var cands []candidate
	for i := range set.list {
		e := &set.list[i]
		if !e.allows(route) || s.TokenBlocked(e.statsKey) {
			continue
		}
		sum := sha256.Sum256([]byte(ip + "\x00" + e.statsKey))
		cands = append(cands, candidate{id: e.statsKey, score: binary.BigEndian.Uint64(sum[:8])})
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		return cands[i].id < cands[j].id
	})
	ids := make([]string, len(cands))
	for i, c := range cands {
		ids[i] = c.id
	}
	return ids
}

// remoteHost returns the IP part of a peer address, without the port.
func remoteHost(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// relayConns copies both directions and closes both ends as soon as either
// direction finishes.
func relayConns(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		_ = dst.Close()
		_ = src.Close()
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}
