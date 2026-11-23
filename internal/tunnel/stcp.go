package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// stcp stream roles carried in X-Tunnel-Role. A visitor is the side that
// accepts local connections; a provider is the side that exposes a local TCP
// service. The server pairs one of each on the same route.
const (
	// TunnelRoleHeader selects the stcp side of a stream.
	TunnelRoleHeader = "X-Tunnel-Role"
	// TunnelRoleProvider marks the stream that represents the exposed service.
	TunnelRoleProvider = "provider"
	// TunnelRoleVisitor marks the stream opened for a local consumer.
	TunnelRoleVisitor = "visitor"
)

// maxSTCPPending bounds queued streams per route and role, so a client that
// opens streams without ever pairing cannot grow the queue without limit.
const maxSTCPPending = 256

// errSTCPNoPeer reports that no stream of the opposite role arrived in time.
var errSTCPNoPeer = errors.New("no stcp peer paired in time")

// stcpWaiter is one stream waiting for its counterpart.
type stcpWaiter struct {
	ch       chan net.Conn // buffered(1); receives the peer's pipe end
	provider string        // provider identity (token stats key); provider streams only
	// ranked lists provider identities in preference order for a server-side
	// exposed visitor. nil means the visitor accepts any provider.
	ranked []string
	queued bool // guarded by stcpHub.mu
}

// stcpQueue holds the streams waiting on one route, per role.
type stcpQueue struct {
	providers []*stcpWaiter
	visitors  []*stcpWaiter
}

// stcpHub pairs provider and visitor streams by route name. Both ends are
// net.Pipe endpoints: the existing data paths (frame reader/writer plus a
// net.Conn) bridge the two HTTP streams without knowing about stcp at all.
type stcpHub struct {
	mu     sync.Mutex
	routes map[string]*stcpQueue
}

func newSTCPHub() *stcpHub {
	return &stcpHub{routes: make(map[string]*stcpQueue)}
}

// pair blocks until a stream of the opposite role arrives on the same route
// and returns one end of the pipe. The waiting peer receives the other end.
// provider identifies the client when role is provider and is ignored for
// visitors. ctx cancellation (client disconnect) and timeout abort the wait.
func (h *stcpHub) pair(ctx context.Context, route, role, provider string, timeout time.Duration) (net.Conn, error) {
	return h.wait(ctx, route, role, provider, nil, timeout)
}

// pairExposed is pair for a visitor opened by the server itself (an exposed
// stcp route). It only pairs with a provider listed in ranked, preferring the
// earliest entry that is online.
func (h *stcpHub) pairExposed(ctx context.Context, route string, ranked []string, timeout time.Duration) (net.Conn, error) {
	return h.wait(ctx, route, TunnelRoleVisitor, "", ranked, timeout)
}

func (h *stcpHub) wait(ctx context.Context, route, role, provider string, ranked []string, timeout time.Duration) (net.Conn, error) {
	w := &stcpWaiter{ch: make(chan net.Conn, 1), provider: provider, ranked: ranked}

	h.mu.Lock()
	q := h.routes[route]
	if q == nil {
		q = &stcpQueue{}
		h.routes[route] = q
	}
	var queue *[]*stcpWaiter
	if role == TunnelRoleProvider {
		if peer := takeVisitorFor(&q.visitors, provider); peer != nil {
			local, remote := net.Pipe()
			peer.ch <- remote
			h.mu.Unlock()
			return local, nil
		}
		queue = &q.providers
	} else {
		if peer := takeProvider(&q.providers, ranked); peer != nil {
			local, remote := net.Pipe()
			peer.ch <- remote
			h.mu.Unlock()
			return local, nil
		}
		queue = &q.visitors
	}
	if len(*queue) >= maxSTCPPending {
		h.mu.Unlock()
		return nil, fmt.Errorf("too many pending %s streams on route %q", role, route)
	}
	*queue = append(*queue, w)
	w.queued = true
	h.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case conn := <-w.ch:
		return conn, nil
	case <-timer.C:
	case <-ctx.Done():
	}

	h.mu.Lock()
	if w.queued {
		removeSTCPWaiter(queue, w)
		w.queued = false
	}
	h.mu.Unlock()
	// A peer may have matched between the timeout firing and the removal.
	select {
	case conn := <-w.ch:
		return conn, nil
	default:
	}
	return nil, errSTCPNoPeer
}

// busyProvider reports how many provider streams are waiting on a route. It is
// used by tests and diagnostics.
func (h *stcpHub) busyProvider(route string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if q := h.routes[route]; q != nil {
		return len(q.providers)
	}
	return 0
}

// takeVisitorFor removes and returns the first visitor that accepts provider:
// a plain visitor accepts any provider, an exposed visitor only the providers
// it ranked.
func takeVisitorFor(list *[]*stcpWaiter, provider string) *stcpWaiter {
	for i, w := range *list {
		if w.ranked == nil || containsID(w.ranked, provider) {
			removeAt(list, i)
			return w
		}
	}
	return nil
}

// takeProvider removes and returns a queued provider. A nil ranking takes the
// oldest provider; otherwise the highest-ranked provider that is queued wins.
func takeProvider(list *[]*stcpWaiter, ranked []string) *stcpWaiter {
	if ranked == nil {
		if len(*list) == 0 {
			return nil
		}
		w := (*list)[0]
		removeAt(list, 0)
		return w
	}
	for _, id := range ranked {
		for i, w := range *list {
			if w.provider == id {
				removeAt(list, i)
				return w
			}
		}
	}
	return nil
}

func containsID(ids []string, id string) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

func removeAt(list *[]*stcpWaiter, i int) {
	q := *list
	*list = append(q[:i], q[i+1:]...)
}

func removeSTCPWaiter(list *[]*stcpWaiter, w *stcpWaiter) {
	q := *list
	for i, cur := range q {
		if cur == w {
			removeAt(list, i)
			return
		}
	}
}
