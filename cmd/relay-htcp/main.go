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
	"syscall"

	"relay-htcp/internal/admin"
	"relay-htcp/internal/admin/ui"
	"relay-htcp/internal/config"
	"relay-htcp/internal/tunnel"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("relay-htcp", version)
	case "help", "--help", "-h":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `relay-htcp - TCP-over-HTTP/2 tunnel

Usage:
  relay-htcp server -config <server.yaml>
  relay-htcp client -config <client.yaml>
  relay-htcp version`)
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

// openAdmin opens the admin database, seeds the default user on first run,
// applies a saved config (it wins over the file config) and builds the admin
// server. It does not open a listener: the caller either mounts the handler on
// the tunnel server (shared mode) or serves it standalone.
func openAdmin(ac config.AdminConfig, provider admin.Provider, configPath string, log *slog.Logger) (*admin.Server, func()) {
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
	}, ui.Handler(), log)

	return asrv, func() {
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
	cfgPath := fs.String("config", "server.yaml", "path to the server config file")
	fs.Parse(args)

	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		fatal(err)
	}
	log := newLogger(cfg.Log.Level)
	srv := tunnel.NewServer(cfg, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.Admin.Enabled {
		asrv, stopAdmin := openAdmin(cfg.Admin, srv, *cfgPath, log)
		defer stopAdmin()
		if cfg.Admin.Shared {
			srv.MountAdmin(cfg.Admin.Path, asrv.Handler())
			log.Info("admin panel mounted on tunnel listener",
				"path", cfg.Admin.Path, "allowed_cidrs", cfg.Admin.AllowedCIDRs)
			if !cfg.TLS.Enabled() {
				log.Warn("admin shares a cleartext tunnel port: use TLS before exposing it publicly",
					"listen", cfg.Listen)
			}
		} else {
			serveAdminStandalone(ctx, asrv, cfg.Admin, log)
		}
	}
	if err := srv.Serve(ctx); err != nil {
		fatal(err)
	}
	log.Info("server stopped")
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	cfgPath := fs.String("config", "client.yaml", "path to the client config file")
	fs.Parse(args)

	cfg, err := config.LoadClient(*cfgPath)
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
	if cfg.Admin.Enabled {
		asrv, stopAdmin := openAdmin(cfg.Admin, pool, *cfgPath, log)
		defer stopAdmin()
		serveAdminStandalone(ctx, asrv, cfg.Admin, log)
	}
	if err := pool.StartListeners(ctx); err != nil {
		fatal(err)
	}
	<-ctx.Done()
	log.Info("client stopped")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "relay-htcp:", err)
	os.Exit(1)
}
