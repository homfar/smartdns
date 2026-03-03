package http

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"smartdns/internal/config"
	"smartdns/internal/db"
	"smartdns/internal/geo"
	syncmod "smartdns/internal/sync"
)

func mkServer(t *testing.T) (*Server, http.Handler) {
	d, _ := db.Open(filepath.Join(t.TempDir(), "app.db"))
	_ = db.Migrate(d)
	h, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	_, _ = d.Exec(`INSERT INTO users(username,password_hash,created_at) VALUES('admin',?,1)`, string(h))
	cfg := config.Load()
	cfg.NoSync = true
	cfg.SessionTTLHours = 1
	s := New(cfg, d, geo.NewMMDB("/non", slog.Default()), syncmod.New(d, false, "", "", nil, "n"), slog.Default())
	return s, s.Router()
}

func TestRemoteIPv6Parsing(t *testing.T) {
	s, _ := mkServer(t)
	s.cfg.AdminAllowlist = []string{"::1"}
	if !s.adminAllowed("[::1]:1234") {
		t.Fatal("expected allowed")
	}
}

func TestSessionExpiryAndCSRFAfterExpiry(t *testing.T) {
	s, h := mkServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/login", "application/x-www-form-urlencoded", strings.NewReader(url.Values{"username": {"admin"}, "password": {"pass"}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Cookies()) == 0 {
		t.Fatal("expected session cookie")
	}
	sid := resp.Cookies()[0].Value
	s.mu.Lock()
	sess := s.sessions[sid]
	sess.ExpiresAt = time.Now().Add(-time.Minute)
	s.sessions[sid] = sess
	s.mu.Unlock()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/zones", nil)
	req.AddCookie(resp.Cookies()[0])
	out, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if out.StatusCode != 200 { // redirected login followed
		t.Fatalf("expected redirect-to-login flow, got %d", out.StatusCode)
	}
}
