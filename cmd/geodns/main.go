package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"smartdns/internal/config"
	"smartdns/internal/db"
	dnssrv "smartdns/internal/dns"
	"smartdns/internal/geo"
	httpapp "smartdns/internal/http"
	syncmod "smartdns/internal/sync"
)

func seedAdmin(d *sql.DB, user, pass string) {
	var c int
	_ = d.QueryRow(`SELECT COUNT(1) FROM users WHERE username=?`, user).Scan(&c)
	if c > 0 {
		return
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	_, _ = d.Exec(`INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)`, user, string(h), time.Now().Unix())
}

func main() {
	cfg := config.Load()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	dbConn, err := db.Open(cfg.DBPath)
	if err != nil {
		panic(err)
	}
	if err = db.Migrate(dbConn); err != nil {
		panic(err)
	}
	seedAdmin(dbConn, cfg.AdminUser, cfg.AdminPassword)
	gp := geo.NewMMDB(cfg.MMDBPath, logger)
	sm := syncmod.New(dbConn, !cfg.NoSync, cfg.PeerURL, cfg.SyncToken, cfg.SyncAllowlist, cfg.NodeID)
	dns := dnssrv.New(dbConn, gp, cfg)
	if err := dns.Start(); err != nil {
		panic(err)
	}
	_ = dropPrivileges(cfg.RunAsUser, cfg.RunAsGroup)
	app := httpapp.New(cfg, dbConn, gp, sm, logger)
	h := &http.Server{Addr: cfg.HTTPAddr, Handler: app.Router()}
	go h.ListenAndServe()
	go periodicBackup(cfg.DBPath, cfg.DBBackupSec, logger)
	go periodicIntegrity(dbConn, cfg.DBIntegritySec, logger)
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for range t.C {
			gp.ReloadIfChanged()
		}
	}()
	if sm.Enabled {
		go func() {
			t := time.NewTicker(time.Duration(cfg.SyncIntervalSec) * time.Second)
			for range t.C {
				_ = sm.PushNow()
			}
		}()
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = h.Shutdown(ctx)
	_ = dns.Shutdown(ctx)
}

func dropPrivileges(userName, groupName string) error {
	if os.Geteuid() != 0 || userName == "" {
		return nil
	}
	u, err := user.Lookup(userName)
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if groupName != "" {
		g, err := user.LookupGroup(groupName)
		if err == nil {
			gid, _ = strconv.Atoi(g.Gid)
		}
	}
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	return syscall.Setuid(uid)
}

func periodicBackup(dbPath string, sec int, logger *slog.Logger) {
	if sec <= 0 {
		return
	}
	t := time.NewTicker(time.Duration(sec) * time.Second)
	defer t.Stop()
	for range t.C {
		in, err := os.Open(dbPath)
		if err != nil {
			continue
		}
		stamp := time.Now().UTC().Format("20060102T150405")
		outPath := filepath.Join(filepath.Dir(dbPath), fmt.Sprintf("%s.%s.bak", filepath.Base(dbPath), stamp))
		out, err := os.Create(outPath)
		if err == nil {
			_, _ = io.Copy(out, in)
			out.Close()
			logger.Info("db backup created", "path", outPath)
		}
		in.Close()
	}
}

func periodicIntegrity(db *sql.DB, sec int, logger *slog.Logger) {
	if sec <= 0 {
		return
	}
	t := time.NewTicker(time.Duration(sec) * time.Second)
	defer t.Stop()
	for range t.C {
		var result string
		if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&result); err != nil || !strings.EqualFold(result, "ok") {
			logger.Error("db integrity check failed", "result", result, "err", err)
		}
	}
}
