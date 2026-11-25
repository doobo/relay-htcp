// Command relay-htcp is a TCP-over-HTTP/2 tunnel: the server side exposes
// intranet TCP services as HTTPS streams, the client side maps local ports
// through the tunnel.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"

	"relay-htcp/internal/admin"
	"relay-htcp/internal/admin/ui"
	"relay-htcp/internal/config"
	"relay-htcp/internal/tunnel"
)

// version is the release version shown by `relay-htcp version`. Release builds
// override it with -ldflags "-X main.version=v1.2.3"; see the Makefile.
var version = "0.1.0"

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		// No subcommand: default to server. With no config file present it
		// starts with the built-in bootstrap config.
		runServer(nil)
		return
	}
	switch args[0] {
	case "server":
		runServer(args[1:])
	case "client":
		runClient(args[1:])
	case "version", "--version", "-v":
		fmt.Println("relay-htcp", version)
	case "help", "--help", "-h":
		usage()
	default:
		if strings.HasPrefix(args[0], "-") {
			// Flags without an explicit subcommand also mean "server".
			runServer(args)
			return
		}
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `relay-htcp - TCP-over-HTTP/2 tunnel

Usage:
  relay-htcp [server] [-config <server.yaml>] [-listen :5630 | -port 5630]
  relay-htcp client [-config <client.yaml>]
  relay-htcp version

Without a subcommand the server starts (built-in defaults when no config file).
Server config is optional: server.yaml is used when present, otherwise built-in
defaults are used (admin panel on /admin, database in ./data/admin.db).
Client config is optional too: data/client.yaml is used when present (then
./client.yaml), otherwise a bootstrap config is created in data/client.yaml
with the admin panel on 127.0.0.1:15630.
Server listen defaults to :5630 when the config omits "listen".
-listen and -port override both the file and the saved database config.`)
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelWarn
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

// openAdmin opens the admin database, seeds the default user on first run,
// applies a saved config (it wins over the file config) and builds the admin
// server. It does not open a listener: the caller either mounts the handler on
// the tunnel server (shared mode) or serves it standalone.
func openAdmin(ac config.AdminConfig, provider admin.Provider, configPath string, log *slog.Logger, restart func()) (*admin.Server, func()) {
	store, err := admin.OpenWithKey(ac.DBPath, ac.KeyFile)
	if err != nil {
		fatal(err)
	}
	if err := store.Migrate(); err != nil {
		fatal(err)
	}

	password := ac.DefaultPassword
	seeded := false
	if password == "" {
		password, err = admin.RandomToken()
		if err != nil {
			fatal(err)
		}
		seeded = true
	}
	hash, err := admin.HashPassword(password)
	if err != nil {
		fatal(err)
	}
	created, err := store.EnsureDefaultUser(ac.DefaultUsername, hash)
	if err != nil {
		fatal(err)
	}
	if created && seeded {
		log.Warn("admin panel: created default user with a generated initial password (shown only once)",
			"user", ac.DefaultUsername, "password", password)
	}

	source := "file"
	if saved, err := store.GetSetting(admin.ConfigKey); err == nil && saved != "" {
		if report, aerr := provider.ApplyConfigYAML(saved); aerr != nil {
			log.Warn("saved config in database rejected, using file config", "err", aerr)
		} else {
			source = "db"
			log.Info("config loaded from database", "restart_required", report.RestartRequired)
		}
	}

	allowlist, err := admin.ParseIPAllowlist(ac.AllowedCIDRs)
	if err != nil {
		_ = store.Close()
		fatal(err)
	}

	asrv := admin.NewServer(store, provider, admin.Options{
		Version:    version,
		Token:      ac.Token,
		SessionTTL: ac.SessionTTL,
		Source:     source,
		ConfigPath: configPath,
		Path:       ac.Path,
		Allowlist:  allowlist,
		Restart:    restart,
	}, ui.Handler(), log)

	return asrv, func() {
		_ = asrv.Traffic().Flush()
		_ = asrv.Close()
		_ = store.Close()
	}
}

// serveAdminStandalone opens the dedicated admin listener (legacy mode).
func serveAdminStandalone(ctx context.Context, asrv *admin.Server, ac config.AdminConfig, log *slog.Logger) {
	ln, err := net.Listen("tcp", ac.Listen)
	if err != nil {
		fatal(err)
	}
	go func() {
		if err := asrv.Serve(ctx, ln); err != nil {
			log.Error("admin panel stopped", "err", err)
		}
	}()
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to the server config (optional; server.yaml is used when present, otherwise built-in defaults)")
	listenFlag := fs.String("listen", "", "listen address override, e.g. :5630 or 0.0.0.0:5630 (default :5630)")
	portFlag := fs.Int("port", 0, "listen port override, e.g. 5630")
	fs.Parse(args)

	cfg, usedConfig, err := loadServerConfig(*cfgPath)
	if err != nil {
		fatal(err)
	}
	log := newLogger(cfg.Log.Level)
	if usedConfig == "" {
		log.Warn("no config file found, using built-in defaults",
			"listen", cfg.Listen, "admin_path", cfg.Admin.Path, "db", cfg.Admin.DBPath)
	}
	srv := tunnel.NewServer(cfg, log)

	override := listenOverride(*listenFlag, *portFlag)
	if override != "" {
		srv.SetListenOverride(override)
	}
	listenAddr := cfg.Listen
	if override != "" {
		listenAddr = override
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var asrv *admin.Server
	stopAdmin := func() {}
	if cfg.Admin.Enabled {
		var closeAdmin func()
		asrv, closeAdmin = openAdmin(cfg.Admin, srv, usedConfig, log, nil)
		stopAdmin = closeAdmin
		asrv.Traffic().Start(ctx)
		srv.SetTraffic(asrv.Traffic())
		if cfg.Admin.Shared {
			srv.MountAdmin(cfg.Admin.Path, asrv.Handler())
			srv.EnableAdminRootRedirect(asrv.Allowlist())
			log.Info("admin panel mounted on tunnel listener",
				"path", cfg.Admin.Path, "allowed_cidrs", cfg.Admin.AllowedCIDRs)
			if !cfg.TLS.Enabled() {
				log.Warn("admin shares a cleartext tunnel port: use TLS before exposing it publicly",
					"listen", listenAddr)
			}
		} else {
			serveAdminStandalone(ctx, asrv, cfg.Admin, log)
		}
	}
	defer stopAdmin()

	// SIGHUP reloads the config file in place (like `nginx -s reload` for the
	// hot-appliable fields) without rebinding the listener or dropping streams.
	watchReloadSignal(ctx, log, func() {
		reloadServerConfig(srv, asrv, usedConfig, log)
	})

	if err := srv.Serve(ctx); err != nil {
		fatal(err)
	}
	log.Info("server stopped")
}

// listenOverride turns the -port / -listen flags into a bind address. An empty
// result means "use the config". A bare port ("5630") is treated as ":5630".
func listenOverride(listen string, port int) string {
	listen = strings.TrimSpace(listen)
	if port > 0 {
		return ":" + strconv.Itoa(port)
	}
	if listen == "" {
		return ""
	}
	if !strings.Contains(listen, ":") {
		return ":" + listen
	}
	return listen
}

// loadServerConfig resolves the server config: an explicit -config path wins;
// otherwise server.yaml in the working directory is used when present; with
// neither, a built-in bootstrap config is returned (and usedConfig is empty, so
// panel saves do not write a file).
func loadServerConfig(explicit string) (*config.ServerConfig, string, error) {
	if explicit != "" {
		cfg, err := config.LoadServer(explicit)
		return cfg, explicit, err
	}
	if st, err := os.Stat("server.yaml"); err == nil && !st.IsDir() {
		cfg, err := config.LoadServer("server.yaml")
		return cfg, "server.yaml", err
	}
	cfg, err := config.BootstrapServer()
	return cfg, "", err
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to the client config (optional; data/client.yaml, then client.yaml, then built-in defaults)")
	fs.Parse(args)

	// Resolve the config once: a restart must reload the same file, not pick
	// a different one after the bootstrap file appears.
	resolved, created, err := resolveClientConfig(*cfgPath)
	if err != nil {
		fatal(err)
	}
	if created {
		newLogger("info").Info("no client config found, created bootstrap config",
			"path", resolved, "admin", "http://127.0.0.1:15630/admin/")
	}

	// The admin panel can request a restart. Reinitialize everything in
	// place: reload the config file (and any config saved in the panel DB),
	// rebuild the tunnel pool, then rebind the listeners.
	for runClientOnce(resolved) {
	}
}

// resolveClientConfig picks the client config file. Without an explicit
// -config it prefers data/client.yaml, then the legacy ./client.yaml. When
// neither exists it writes a bootstrap config to data/client.yaml (admin
// panel only) and returns that path.
func resolveClientConfig(explicit string) (path string, created bool, err error) {
	if explicit != "" {
		return explicit, false, nil
	}
	candidates := []string{
		filepath.Join("data", "client.yaml"),
		"client.yaml",
	}
	for _, p := range candidates {
		if st, serr := os.Stat(p); serr == nil && !st.IsDir() {
			return p, false, nil
		}
	}
	cfg, err := config.BootstrapClient()
	if err != nil {
		return "", false, err
	}
	path = filepath.Join("data", "client.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", false, err
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return "", false, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", false, err
	}
	return path, true, nil
}

// runClientOnce runs one client lifecycle. It returns true when the admin
// panel requested a restart, false when the process should exit.
func runClientOnce(cfgPath string) bool {
	cfg, err := config.LoadClient(cfgPath)
	if err != nil {
		fatal(err)
	}
	log := newLogger(cfg.Log.Level)
	pool, err := tunnel.NewPool(cfg, log)
	if err != nil {
		fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool.Start(ctx)

	restartCh := make(chan struct{}, 1)
	requestRestart := func() {
		select {
		case restartCh <- struct{}{}:
		default:
		}
	}

	stopAdmin := func() {}
	if cfg.Admin.Enabled {
		asrv, closeAdmin := openAdmin(cfg.Admin, pool, cfgPath, log, requestRestart)
		stopAdmin = closeAdmin
		asrv.Traffic().Start(ctx)
		pool.SetTraffic(asrv.Traffic())
		serveAdminStandalone(ctx, asrv, cfg.Admin, log)
	}
	if err := pool.StartListeners(ctx); err != nil {
		stopAdmin()
		fatal(err)
	}
	if err := pool.StartProviders(ctx); err != nil {
		pool.StopAllListeners()
		stopAdmin()
		fatal(err)
	}

	select {
	case <-ctx.Done():
		pool.StopAllListeners()
		pool.StopAllProviders()
		stopAdmin()
		log.Info("client stopped")
		return false
	case <-restartCh:
		log.Info("client restarting (requested from admin panel)")
		// Release every listening socket before the next iteration binds
		// them again.
		pool.StopAllListeners()
		pool.StopAllProviders()
		stop()
		stopAdmin()
		return true
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "relay-htcp:", err)
	os.Exit(1)
}
