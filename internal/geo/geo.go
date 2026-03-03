package geo

import (
	"log/slog"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

type Provider interface {
	CountryCode(net.IP) string
	Healthy() bool
	ReloadIfChanged()
}

type MMDBProvider struct {
	mu       sync.RWMutex
	db       *maxminddb.Reader
	path     string
	modTime  time.Time
	lastWarn time.Time
	logger   *slog.Logger
}

type countryResp struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

var geoCountryLookups atomic.Uint64
var geoIranDecisions atomic.Uint64
var geoForeignDecisions atomic.Uint64

func NewMMDB(path string, logger *slog.Logger) *MMDBProvider {
	p := &MMDBProvider{logger: logger, path: path}
	p.open(path)
	return p
}

func (m *MMDBProvider) open(path string) {
	if path == "" {
		return
	}
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	db, err := maxminddb.Open(path)
	if err == nil {
		m.mu.Lock()
		if m.db != nil {
			_ = m.db.Close()
		}
		m.db = db
		m.modTime = st.ModTime()
		m.mu.Unlock()
	}
}

func (m *MMDBProvider) ReloadIfChanged() {
	if m.path == "" {
		return
	}
	st, err := os.Stat(m.path)
	if err != nil {
		return
	}
	m.mu.RLock()
	need := st.ModTime().After(m.modTime)
	m.mu.RUnlock()
	if need {
		m.open(m.path)
	}
}

func (m *MMDBProvider) Healthy() bool { m.mu.RLock(); defer m.mu.RUnlock(); return m.db != nil }
func (m *MMDBProvider) CountryCode(ip net.IP) string {
	geoCountryLookups.Add(1)
	m.mu.RLock()
	db := m.db
	m.mu.RUnlock()
	if db == nil {
		if time.Since(m.lastWarn) > time.Minute {
			m.logger.Warn("mmdb unavailable; GEO defaults by fallback")
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

func SelectA(country, iranIP, foreignIP, fallback string) string {
	if country == "IR" && iranIP != "" {
		geoIranDecisions.Add(1)
		return iranIP
	}
	switch strings.ToUpper(fallback) {
	case "IR":
		if iranIP != "" {
			geoIranDecisions.Add(1)
			return iranIP
		}
	case "RANDOM":
		if rand.Intn(2) == 0 && iranIP != "" {
			geoIranDecisions.Add(1)
			return iranIP
		}
	}
	geoForeignDecisions.Add(1)
	return foreignIP
}

func Metrics() (uint64, uint64, uint64) {
	return geoCountryLookups.Load(), geoIranDecisions.Load(), geoForeignDecisions.Load()
}
