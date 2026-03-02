package main

import (
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
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
	dns := dnssrv.New(dbConn, gp, cfg.DNSAddr)
	_ = dns.Start()
	app := httpapp.New(cfg, dbConn, gp, sm, logger)
	h := &http.Server{Addr: cfg.HTTPAddr, Handler: app.Router()}
	go h.ListenAndServe()
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
}
