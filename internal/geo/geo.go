package geo

import (
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

type Provider interface {
	CountryCode(net.IP) string
	Healthy() bool
}

type MMDBProvider struct {
	mu       sync.RWMutex
	db       *maxminddb.Reader
	lastWarn time.Time
	logger   *slog.Logger
}

type countryResp struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

func NewMMDB(path string, logger *slog.Logger) *MMDBProvider {
	p := &MMDBProvider{logger: logger}
	db, err := maxminddb.Open(path)
	if err == nil {
		p.db = db
	}
	return p
}
func (m *MMDBProvider) Healthy() bool { m.mu.RLock(); defer m.mu.RUnlock(); return m.db != nil }
func (m *MMDBProvider) CountryCode(ip net.IP) string {
	m.mu.RLock()
	db := m.db
	m.mu.RUnlock()
	if db == nil {
		if time.Since(m.lastWarn) > time.Minute {
			m.logger.Warn("mmdb unavailable; GEO defaults to foreign")
			m.lastWarn = time.Now()
		}
		return ""
	}
	var r countryResp
	if err := db.Lookup(ip, &r); err != nil {
		return ""
	}
	return r.Country.ISOCode
}

func SelectA(country, iranIP, foreignIP string) string {
	if country == "IR" {
		return iranIP
	}
	return foreignIP
}
