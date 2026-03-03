package http

import (
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"smartdns/internal/config"
	"smartdns/internal/db"
	"smartdns/internal/geo"
	syncmod "smartdns/internal/sync"
)

func TestRateLimiterConcurrent(t *testing.T) {
	d, _ := db.Open(filepath.Join(t.TempDir(), "app.db"))
	_ = db.Migrate(d)
	cfg := config.Load()
	cfg.APIRatePerMin = 1000
	s := New(cfg, d, geo.NewMMDB("", slog.Default()), syncmod.New(d, false, "", "", nil, "n"), slog.Default())
	h := s.Router()
	wg := sync.WaitGroup{}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("GET", "/readyz", nil)
			r.RemoteAddr = "127.0.0.1:12345"
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
		}()
	}
	wg.Wait()
}
