package config

import (
	"strings"
	"testing"
)

func bindConfig(routes ...Route) *ServerConfig {
	return &ServerConfig{
		Listen: ":5630",
		Auth:   AuthConfig{Tokens: []Token{{Name: "a", Token: "tok-a"}}},
		Routes: routes,
	}
}

func TestServerRouteBindValidation(t *testing.T) {
	ok := []Route{
		{Name: "loop", Type: RouteTypeSTCP, Bind: "127.0.0.1:1234"},
		{Name: "all", Type: RouteTypeSTCP, Bind: "0.0.0.0:1235"},
		{Name: "tcp", Target: "127.0.0.1:22"},
	}
	if err := bindConfig(ok...).Validate(); err != nil {
		t.Fatalf("valid bind rejected: %v", err)
	}

	cases := map[string]struct {
		routes []Route
		want   string
	}{
		"bind on tcp route": {
			[]Route{{Name: "x", Target: "127.0.0.1:22", Bind: "127.0.0.1:1234"}},
			"only supported for stcp",
		},
		"missing port": {
			[]Route{{Name: "x", Type: RouteTypeSTCP, Bind: "127.0.0.1"}},
			"must be host:port",
		},
		"port out of range": {
			[]Route{{Name: "x", Type: RouteTypeSTCP, Bind: "127.0.0.1:70000"}},
			"invalid port",
		},
		"duplicate bind": {
			[]Route{
				{Name: "a", Type: RouteTypeSTCP, Bind: "127.0.0.1:1234"},
				{Name: "b", Type: RouteTypeSTCP, Bind: "127.0.0.1:1234"},
			},
			"duplicate bind",
		},
		"same as listen": {
			[]Route{{Name: "a", Type: RouteTypeSTCP, Bind: ":5630"}},
			"must differ from listen",
		},
	}
	for name, tc := range cases {
		err := bindConfig(tc.routes...).Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", name, err, tc.want)
		}
	}
}
