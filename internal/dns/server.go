package dns

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"
	"smartdns/internal/config"
	"smartdns/internal/geo"
	"smartdns/internal/validate"
)

type tokenBucket struct {
	tokens float64
	last   time.Time
}

type Server struct {
	db   *sql.DB
	geo  geo.Provider
	cfg  config.Config
	addr string
	udp  *mdns.Server
	tcp  *mdns.Server

	mu          sync.Mutex
	rrl         map[string]*tokenBucket
	tcpPerIP    map[string]int
	currentTCP  atomic.Int64
	queryCounts map[uint16]*atomic.Uint64
	latencyNS   []int64
}

func New(db *sql.DB, gp geo.Provider, cfg config.Config) *Server {
	qc := map[uint16]*atomic.Uint64{}
	for _, rt := range []uint16{mdns.TypeA, mdns.TypeAAAA, mdns.TypeMX, mdns.TypeNS, mdns.TypeTXT, mdns.TypeCNAME, mdns.TypeSOA, mdns.TypeANY} {
		qc[rt] = &atomic.Uint64{}
	}
	return &Server{db: db, geo: gp, cfg: cfg, addr: cfg.DNSAddr, rrl: map[string]*tokenBucket{}, tcpPerIP: map[string]int{}, queryCounts: qc}
}

func (s *Server) Start() error {
	h := mdns.HandlerFunc(s.handle)
	s.udp = &mdns.Server{Addr: s.addr, Net: "udp", Handler: h, ReusePort: true, UDPSize: uint16(s.cfg.DNSMaxUDPSize), ReadTimeout: time.Duration(s.cfg.DNSTimeoutMS) * time.Millisecond, WriteTimeout: time.Duration(s.cfg.DNSTimeoutMS) * time.Millisecond}
	s.tcp = &mdns.Server{Addr: s.addr, Net: "tcp", Handler: h, ReusePort: true, ReadTimeout: time.Duration(s.cfg.DNSTimeoutMS) * time.Millisecond, WriteTimeout: time.Duration(s.cfg.DNSTimeoutMS) * time.Millisecond, MaxTCPQueries: 64}
	go s.udp.ListenAndServe()
	go s.tcp.ListenAndServe()
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	var errs []error
	if s.udp != nil {
		errs = append(errs, s.udp.ShutdownContext(ctx))
	}
	if s.tcp != nil {
		errs = append(errs, s.tcp.ShutdownContext(ctx))
	}
	return errors.Join(errs...)
}

func (s *Server) Healthy() bool { return s.udp != nil && s.tcp != nil }

func LongestZone(name string, zones []string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	best := ""
	for _, z := range zones {
		if name == z || strings.HasSuffix(name, "."+z) {
			if len(z) > len(best) {
				best = z
			}
		}
	}
	return best
}

func (s *Server) allowIP(ip string) bool {
	if !s.cfg.DNSRRLEnabled {
		return true
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.rrl[ip]
	if !ok {
		b = &tokenBucket{tokens: float64(s.cfg.DNSRRLRate), last: now}
		s.rrl[ip] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * float64(s.cfg.DNSRRLRate)
	if b.tokens > float64(s.cfg.DNSRRLRate) {
		b.tokens = float64(s.cfg.DNSRRLRate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (s *Server) handle(w mdns.ResponseWriter, r *mdns.Msg) {
	start := time.Now()
	defer func() { s.latencyNS = append(s.latencyNS, time.Since(start).Nanoseconds()) }()
	m := new(mdns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Compress = true
	m.SetEdns0(uint16(s.cfg.DNSMaxUDPSize), true)
	if len(r.Question) == 0 {
		_ = w.WriteMsg(m)
		return
	}
	host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	if host == "" {
		host = w.RemoteAddr().String()
	}
	if !s.allowIP(host) {
		m.Rcode = mdns.RcodeServerFailure
		_ = w.WriteMsg(m)
		return
	}
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		s.mu.Lock()
		if s.currentTCP.Load() >= int64(s.cfg.DNSMaxTCP) || s.tcpPerIP[host] >= s.cfg.DNSPerIPTCP {
			s.mu.Unlock()
			m.Rcode = mdns.RcodeRefused
			_ = w.WriteMsg(m)
			return
		}
		s.currentTCP.Add(1)
		s.tcpPerIP[host]++
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			s.currentTCP.Add(-1)
			s.tcpPerIP[host]--
			s.mu.Unlock()
		}()
	}
	q := r.Question[0]
	if c, ok := s.queryCounts[q.Qtype]; ok {
		c.Add(1)
	}
	if q.Qclass == mdns.ClassCHAOS {
		m.Answer = []mdns.RR{&mdns.TXT{Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassCHAOS, Ttl: 0}, Txt: []string{"ok"}}}
		_ = w.WriteMsg(m)
		return
	}
	if q.Qtype == mdns.TypeAXFR || q.Qtype == mdns.TypeIXFR {
		m.Rcode = mdns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	qName := validate.NormalizeDomain(q.Name)
	zones, _ := s.allZones()
	zone := LongestZone(qName, zones)
	if zone == "" {
		m.Rcode = mdns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	zoneID, soa := s.zoneInfo(zone)
	recs := s.lookup(zoneID, qName, q.Qtype, zone, host)
	if len(recs) == 0 {
		if !s.nameExists(zoneID, qName, zone) {
			m.Rcode = mdns.RcodeNameError
		}
		m.Ns = append(m.Ns, soa)
		_ = w.WriteMsg(m)
		return
	}
	if q.Qtype == mdns.TypeANY {
		if len(recs) > 1 {
			recs = recs[:1]
		}
	}
	m.Answer = recs
	if w.LocalAddr().Network() == "udp" && m.Len() > s.cfg.DNSMaxUDPSize {
		m.Truncated = true
		m.Answer = nil
	}
	_ = w.WriteMsg(m)
}

func (s *Server) allZones() ([]string, error) {
	rows, err := s.db.Query(`SELECT domain FROM zones WHERE enabled=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var z string
		_ = rows.Scan(&z)
		out = append(out, z)
	}
	return out, nil
}
func (s *Server) zoneInfo(domain string) (int64, mdns.RR) {
	var id int64
	var mname, rname string
	var serial int64
	var refresh, retry, expire, minimum int
	_ = s.db.QueryRow(`SELECT id,soa_mname,soa_rname,soa_serial,soa_refresh,soa_retry,soa_expire,soa_minimum FROM zones WHERE domain=?`, domain).Scan(&id, &mname, &rname, &serial, &refresh, &retry, &expire, &minimum)
	return id, &mdns.SOA{Hdr: mdns.RR_Header{Name: mdns.Fqdn(domain), Rrtype: mdns.TypeSOA, Class: mdns.ClassINET, Ttl: uint32(minimum)}, Ns: mdns.Fqdn(mname), Mbox: mdns.Fqdn(rname), Serial: uint32(serial), Refresh: uint32(refresh), Retry: uint32(retry), Expire: uint32(expire), Minttl: uint32(minimum)}
}
func (s *Server) nameExists(zoneID int64, fqdn, zone string) bool {
	rel := "@"
	if fqdn != zone {
		rel = strings.TrimSuffix(strings.TrimSuffix(fqdn, "."+zone), ".")
	}
	var c int
	_ = s.db.QueryRow(`SELECT COUNT(1) FROM records WHERE zone_id=? AND enabled=1 AND (name=? OR name='*')`, zoneID, rel).Scan(&c)
	return c > 0
}
func (s *Server) lookup(zoneID int64, fqdn string, qt uint16, zone, remote string) []mdns.RR {
	rel := "@"
	if fqdn != zone {
		rel = strings.TrimSuffix(strings.TrimSuffix(fqdn, "."+zone), ".")
	}
	rows, _ := s.db.Query(`SELECT type,ttl,data_json,name FROM records WHERE zone_id=? AND enabled=1 AND (name=? OR name='*')`, zoneID, rel)
	defer rows.Close()
	var out []mdns.RR
	haveCNAME := false
	for rows.Next() {
		var typ, data, recName string
		var ttl int
		_ = rows.Scan(&typ, &ttl, &data, &recName)
		if qt != mdns.TypeANY && mdns.StringToType[typ] != qt {
			continue
		}
		if ttl < s.cfg.TTLMin || ttl > s.cfg.TTLMax {
			continue
		}
		h := mdns.RR_Header{Name: mdns.Fqdn(fqdn), Rrtype: mdns.StringToType[typ], Class: mdns.ClassINET, Ttl: uint32(ttl)}
		if recName == "*" && rel != "*" {
			h.Name = mdns.Fqdn(fqdn)
		}
		var p map[string]any
		_ = json.Unmarshal([]byte(data), &p)
		switch typ {
		case "A":
			ip := ""
			if p["mode"] == "GEO" {
				iran, _ := p["iran_ip"].(string)
				foreign, _ := p["foreign_ip"].(string)
				ip = geo.SelectA(s.geo.CountryCode(net.ParseIP(remote)), iran, foreign, s.cfg.GeoFallback)
			} else {
				ip, _ = p["ip"].(string)
			}
			out = append(out, &mdns.A{Hdr: h, A: net.ParseIP(ip)})
		case "AAAA":
			ip, _ := p["ip"].(string)
			out = append(out, &mdns.AAAA{Hdr: h, AAAA: net.ParseIP(ip)})
		case "TXT":
			vals := []string{}
			if arr, ok := p["texts"].([]any); ok {
				for _, v := range arr {
					if t, ok := v.(string); ok {
						vals = append(vals, t)
					}
				}
			}
			out = append(out, &mdns.TXT{Hdr: h, Txt: vals})
		case "CNAME":
			target, _ := p["target"].(string)
			haveCNAME = true
			out = append(out, &mdns.CNAME{Hdr: h, Target: mdns.Fqdn(target)})
		case "MX":
			exchange, _ := p["exchange"].(string)
			pref, _ := p["preference"].(float64)
			out = append(out, &mdns.MX{Hdr: h, Mx: mdns.Fqdn(exchange), Preference: uint16(pref)})
		case "NS":
			host, _ := p["host"].(string)
			out = append(out, &mdns.NS{Hdr: h, Ns: mdns.Fqdn(host)})
		}
	}
	if haveCNAME {
		cn := []mdns.RR{}
		for _, rr := range out {
			if rr.Header().Rrtype == mdns.TypeCNAME {
				cn = append(cn, rr)
			}
		}
		return cn
	}
	return out
}
