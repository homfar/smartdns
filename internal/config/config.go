package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	DBPath          string
	MMDBPath        string
	HTTPAddr        string
	DNSAddr         string
	NoSync          bool
	PeerURL         string
	SyncToken       string
	SyncAllowlist   []string
	NodeID          string
	AdminUser       string
	AdminPassword   string
	SessionSecret   string
	SyncIntervalSec int
	TTLMin          int
	TTLMax          int
	DNSRRLEnabled   bool
	DNSRRLRate      int
	DNSMaxTCP       int
	DNSMaxUDPSize   int
	DNSPerIPTCP     int
	DNSTimeoutMS    int
	GeoFallback     string
	AdminAllowlist  []string
	APIRatePerMin   int
	RunAsUser       string
	RunAsGroup      string
	GEORequired     bool
	DBBackupSec     int
	DBIntegritySec  int
}

func Load() Config {
	return Config{
		DBPath:          getenv("DB_PATH", "/data/app.db"),
		MMDBPath:        getenv("MMDB_PATH", "/mmdb/GeoLite2-Country.mmdb"),
		HTTPAddr:        getenv("HTTP_ADDR", ":5555"),
		DNSAddr:         getenv("DNS_ADDR", ":53"),
		NoSync:          getenv("NO_SYNC", "true") == "true",
		PeerURL:         getenv("PEER_URL", ""),
		SyncToken:       getenv("SYNC_TOKEN", ""),
		SyncAllowlist:   split(getenv("SYNC_ALLOWLIST", "")),
		NodeID:          getenv("NODE_ID", "node-1"),
		AdminUser:       getenv("ADMIN_USER", "admin"),
		AdminPassword:   getenv("ADMIN_PASSWORD", "admin123"),
		SessionSecret:   getenv("SESSION_SECRET", "change-me-32-bytes-minimum"),
		SyncIntervalSec: atoi(getenv("SYNC_INTERVAL_SEC", "30"), 30),
		TTLMin:          atoi(getenv("TTL_MIN", "30"), 30),
		TTLMax:          atoi(getenv("TTL_MAX", "86400"), 86400),
		DNSRRLEnabled:   getenv("DNS_RRL_ENABLED", "true") == "true",
		DNSRRLRate:      atoi(getenv("DNS_RRL_RATE", "20"), 20),
		DNSMaxTCP:       atoi(getenv("DNS_MAX_TCP", "100"), 100),
		DNSMaxUDPSize:   atoi(getenv("DNS_MAX_UDP_SIZE", "1232"), 1232),
		DNSPerIPTCP:     atoi(getenv("DNS_PER_IP_TCP", "10"), 10),
		DNSTimeoutMS:    atoi(getenv("DNS_QUERY_TIMEOUT_MS", "2000"), 2000),
		GeoFallback:     strings.ToUpper(getenv("GEO_FALLBACK", "FOREIGN")),
		AdminAllowlist:  split(getenv("ADMIN_ALLOWLIST", "")),
		APIRatePerMin:   atoi(getenv("API_RATE_PER_MIN", "120"), 120),
		RunAsUser:       getenv("RUN_AS_USER", ""),
		RunAsGroup:      getenv("RUN_AS_GROUP", ""),
		GEORequired:     getenv("GEO_REQUIRED", "false") == "true",
		DBBackupSec:     atoi(getenv("DB_BACKUP_SEC", "300"), 300),
		DBIntegritySec:  atoi(getenv("DB_INTEGRITY_SEC", "600"), 600),
	}
}

func getenv(k, d string) string {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	return v
}
func atoi(s string, d int) int {
	v, e := strconv.Atoi(s)
	if e != nil {
		return d
	}
	return v
}
func split(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
