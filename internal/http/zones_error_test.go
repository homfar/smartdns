package http

import (
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"smartdns/internal/config"
	"smartdns/internal/db"
	"smartdns/internal/geo"
	syncmod "smartdns/internal/sync"
)

func TestZonesListReturns500OnDBError(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	cfg := config.Load()
	cfg.NoSync = true
	s := New(cfg, d, geo.NewMMDB("/non", slog.Default()), syncmod.New(d, false, "", "", nil, "n"), slog.Default())
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/zones", nil)
	rr := httptest.NewRecorder()
	s.zonesList(rr, req)
	if rr.Code != 500 {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
}
