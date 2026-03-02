package http

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"smartdns/internal/config"
	"smartdns/internal/db"
	"smartdns/internal/geo"
	syncmod "smartdns/internal/sync"
)

func TestLogin(t *testing.T) {
	d, _ := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	h, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	_, _ = d.Exec(`INSERT INTO users(username,password_hash,created_at) VALUES('admin',?,1)`, string(h))
	cfg := config.Load()
	cfg.NoSync = true
	s := New(cfg, d, geo.NewMMDB("/non", slog.Default()), syncmod.New(d, false, "", "", nil, "n"), slog.Default())
	ts := httptest.NewServer(s.Router())
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/login", "application/x-www-form-urlencoded", strings.NewReader(url.Values{"username": {"admin"}, "password": {"pass"}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode >= 500 {
		t.Fatal(resp.StatusCode)
	}
}
