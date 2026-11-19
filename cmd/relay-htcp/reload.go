package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"relay-htcp/internal/admin"
	"relay-htcp/internal/config"
	"relay-htcp/internal/tunnel"
)

// watchReloadSignal reloads the server config on every SIGHUP until ctx ends.
// SIGHUP is the nginx-style "reload" hook: it only rewrites settings that can
// be applied in place, so live tunnels are never dropped. It returns
// immediately; the watcher runs in the background.
func watchReloadSignal(ctx context.Context, log *slog.Logger, doReload func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		defer signal.Stop(ch)
		watchReload(ctx, ch, log, doReload)
	}()
}

// watchReload is the testable core of watchReloadSignal.
func watchReload(ctx context.Context, ch <-chan os.Signal, log *slog.Logger, doReload func()) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			log.Info("SIGHUP received: reloading configuration")
			doReload()
		}
	}
}

// reloadServerConfig re-reads the config file, hot-applies it, reloads the TLS
// certificate and mirrors the result into the admin database (which wins at
// the next start). Restart-only fields are reported, never silently ignored.
// The running config is kept when the file is missing or invalid; the returned
// report is then zero and the error explains why.
func reloadServerConfig(srv *tunnel.Server, asrv *admin.Server, path string, log *slog.Logger) (admin.SaveReport, error) {
	if path == "" {
		log.Warn("reload skipped: no config file (start with -config to enable SIGHUP reload)")
		return admin.SaveReport{}, nil
	}
	newCfg, err := config.LoadServer(path)
	if err != nil {
		log.Error("reload failed, keeping the running config", "path", path, "err", err)
		return admin.SaveReport{}, err
	}
	report, err := srv.ApplyConfig(newCfg)
	if err != nil {
		log.Error("reload failed, keeping the running config", "path", path, "err", err)
		return admin.SaveReport{}, err
	}
	if asrv != nil {
		if err := asrv.PersistConfig(); err != nil {
			log.Warn("reloaded config not persisted to the admin database", "err", err)
		}
	}
	if len(report.RestartRequired) > 0 {
		log.Warn("reload: these fields need a process restart", "fields", report.RestartRequired)
	}
	log.Info("configuration reloaded", "path", path,
		"applied", report.Applied, "restart_required", report.RestartRequired)
	return report, nil
}
