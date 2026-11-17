package tunnel

import (
	"context"
	"net"
	"testing"
	"time"

	"relay-htcp/internal/config"
)

func slotWithTunnel(t *tunnel) *slot {
	s := &slot{}
	s.set(t)
	return s
}

func liveTestTunnel(server string) *tunnel {
	return &tunnel{server: server, dead: make(chan struct{})}
}

func testServer(name string, tunnels ...*tunnel) *serverState {
	srv := &serverState{name: name}
	for _, t := range tunnels {
		srv.slots = append(srv.slots, slotWithTunnel(t))
	}
	return srv
}

// TestPoolPickFailover verifies that a failover listener always stays on the
// first selected server and only moves to the next one while it is down.
func TestPoolPickFailover(t *testing.T) {
	aTunnel := liveTestTunnel("a")
	a := testServer("a", aTunnel)
	b := testServer("b", liveTestTunnel("b"))
	p := &Pool{servers: []*serverState{a, b}}

	for i := 0; i < 5; i++ {
		if got := p.pick([]*serverState{a, b}, config.StrategyFailover); got == nil || got.server != "a" {
			t.Fatalf("pick %d = %+v, want server a", i, got)
		}
	}

	aTunnel.close()
	for i := 0; i < 5; i++ {
		if got := p.pick([]*serverState{a, b}, config.StrategyFailover); got == nil || got.server != "b" {
			t.Fatalf("after a down, pick %d = %+v, want server b", i, got)
		}
	}
}

// TestPoolPickRoundRobin verifies that round_robin spreads connections across
// the selected servers.
func TestPoolPickRoundRobin(t *testing.T) {
	a := testServer("a", liveTestTunnel("a"))
	b := testServer("b", liveTestTunnel("b"))
	p := &Pool{servers: []*serverState{a, b}}

	counts := map[string]int{}
	for i := 0; i < 10; i++ {
		got := p.pick([]*serverState{a, b}, config.StrategyRoundRobin)
		if got == nil {
			t.Fatalf("pick %d returned nil", i)
		}
		counts[got.server]++
	}
	if counts["a"] != 5 || counts["b"] != 5 {
		t.Fatalf("round_robin distribution = %v, want 5/5", counts)
	}
}

// TestPoolPickSkipsDeadServer verifies that round_robin falls through to a
// live server when its first choice is down.
func TestPoolPickSkipsDeadServer(t *testing.T) {
	a := testServer("a", liveTestTunnel("a"))
	b := testServer("b", liveTestTunnel("b"))
	a.slots[0].get().close()
	p := &Pool{servers: []*serverState{a, b}}

	for i := 0; i < 10; i++ {
		if got := p.pick([]*serverState{a, b}, config.StrategyRoundRobin); got == nil || got.server != "b" {
			t.Fatalf("pick %d = %+v, want server b", i, got)
		}
	}
}

// TestFailoverOnStreamFailure verifies that a data stream rejected by the
// first server (for example because its route target is down) is retried on
// the next server of a failover listener.
func TestFailoverOnStreamFailure(t *testing.T) {
	echoAddr, stopEcho := echoTarget(t)
	defer stopEcho()
	badAddr, stopBad := startTunnelServer(t, "127.0.0.1:1", false)
	defer stopBad()
	goodAddr, stopGood := startTunnelServer(t, echoAddr, false)
	defer stopGood()

	cfg := &config.ClientConfig{
		Auth: config.ClientAuth{Token: testToken},
		Servers: []config.ServerEndpoint{
			{Name: "bad", URL: badAddr},
			{Name: "good", URL: goodAddr},
		},
		Listeners: []config.Listener{{
			Local: "127.0.0.1:0", Target: "echo",
			Servers: []string{"bad", "good"}, Strategy: config.StrategyFailover,
		}},
	}
	cfg.Tunnel.Connections = 1
	cfg.Tunnel.Heartbeat = 2 * time.Second
	cfg.Tunnel.HeartbeatMiss = 3
	cfg.Tunnel.ReconnectMin = 200 * time.Millisecond
	cfg.Tunnel.ReconnectMax = 2 * time.Second
	cfg.Tunnel.StreamTimeout = 10 * time.Second
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool.Start(ctx)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.Listeners[0]
	l.Local = ln.Addr().String()
	go pool.ServeListener(ctx, ln, l)
	defer ln.Close()

	testEchoRoundTrip(t, ln.Addr().String(), "failover")
}

// TestPoolEligibleServers verifies the listener's server selection order.
func TestPoolEligibleServers(t *testing.T) {
	a := testServer("a")
	b := testServer("b")
	c := testServer("c")
	p := &Pool{servers: []*serverState{a, b, c}}

	if got := p.eligibleServers(config.Listener{}); len(got) != 3 {
		t.Fatalf("empty selection = %d servers, want all 3", len(got))
	}
	got := p.eligibleServers(config.Listener{Servers: []string{"c", "a"}})
	if len(got) != 2 || got[0].name != "c" || got[1].name != "a" {
		t.Fatalf("selection = %+v, want c then a", got)
	}
	if got := p.eligibleServers(config.Listener{Servers: []string{"missing"}}); len(got) != 0 {
		t.Fatalf("unknown selection = %d servers, want 0", len(got))
	}
}
