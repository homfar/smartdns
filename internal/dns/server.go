package dns

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"smartdns/internal/config"
	"smartdns/internal/geo"
	"smartdns/internal/validate"
)

var (
	dnsMetricsOnce sync.Once
	dnsLatencyVec  *prometheus.HistogramVec
	dnsRcodesVec   *prometheus.CounterVec
	dnsQtypesVec   *prometheus.CounterVec
)

type tokenBucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

type Server struct {
	db  *sql.DB
	geo geo.Provider
	cfg config.Config

	udp []*mdns.Server
	tcp []*mdns.Server

	mu         sync.Mutex
	rrl        map[string]*tokenBucket
	tcpPerIP   map[string]int
	currentTCP atomic.Int64

	queryCounts map[uint16]*atomic.Uint64

	dnsLatency *prometheus.HistogramVec
	dnsRcodes  *prometheus.CounterVec
	dnsQtypes  *prometheus.CounterVec

	cleanupCancel context.CancelFunc
	invalidLogTS  atomic.Int64
}

func New(db *sql.DB, gp geo.Provider, cfg config.Config) *Server {
	qc := map[uint16]*atomic.Uint64{}
	for _, rt := range []uint16{mdns.TypeA, mdns.TypeAAAA, mdns.TypeMX, mdns.TypeNS, mdns.TypeTXT, mdns.TypeCNAME, mdns.TypeSOA, mdns.TypeSRV, mdns.TypeCAA, mdns.TypeANY} {
		qc[rt] = &atomic.Uint64{}
	}
	dnsMetricsOnce.Do(func() {
		dnsLatencyVec = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "dns_request_duration_seconds", Help: "DNS request duration", Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25}}, []string{"proto"})
		dnsRcodesVec = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dns_rcode_total", Help: "DNS rcode count"}, []string{"rcode"})
		dnsQtypesVec = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "dns_queries_total", Help: "DNS queries by qtype"}, []string{"qtype"})
		prometheus.MustRegister(dnsLatencyVec, dnsRcodesVec, dnsQtypesVec)
	})

	addrs := cfg.DNSAddrs
	if len(addrs) == 0 {
		addrs = []string{cfg.DNSAddr}
	}
	s := &Server{db: db, geo: gp, cfg: cfg, rrl: map[string]*tokenBucket{}, tcpPerIP: map[string]int{}, queryCounts: qc, dnsLatency: dnsLatencyVec, dnsRcodes: dnsRcodesVec, dnsQtypes: dnsQtypesVec}
	ctx, cancel := context.WithCancel(context.Background())
	s.cleanupCancel = cancel
	go s.cleanupRRL(ctx)
	return s
}

func (s *Server) Start() error {
	h := mdns.HandlerFunc(s.handle)
	addrs := s.cfg.DNSAddrs
	if len(addrs) == 0 {
		addrs = []string{s.cfg.DNSAddr}
	}
	for _, addr := range addrs {
		udp := &mdns.Server{Addr: addr, Net: "udp", Handler: h, ReusePort: true, UDPSize: s.cfg.DNSMaxUDPSize, ReadTimeout: time.Duration(s.cfg.DNSTimeoutMS) * time.Millisecond, WriteTimeout: time.Duration(s.cfg.DNSTimeoutMS) * time.Millisecond}
		tcp := &mdns.Server{Addr: addr, Net: "tcp", Handler: h, ReusePort: true, ReadTimeout: time.Duration(s.cfg.DNSTimeoutMS) * time.Millisecond, WriteTimeout: time.Duration(s.cfg.DNSTimeoutMS) * time.Millisecond, MaxTCPQueries: 64}
		s.udp = append(s.udp, udp)
		s.tcp = append(s.tcp, tcp)
		go udp.ListenAndServe()
		go tcp.ListenAndServe()
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.cleanupCancel != nil {
		s.cleanupCancel()
	}
	var errs []error
	for _, srv := range s.udp {
		errs = append(errs, srv.ShutdownContext(ctx))
	}
	for _, srv := range s.tcp {
		errs = append(errs, srv.ShutdownContext(ctx))
	}
	return errors.Join(errs...)
}

func (s *Server) Healthy() bool { return len(s.udp) > 0 && len(s.tcp) > 0 }

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

func (s *Server) cleanupRRL(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(max(60, s.cfg.DNSRRLWindowSec)) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for ip, b := range s.rrl {
				if now.Sub(b.lastSeen) > time.Duration(max(300, s.cfg.DNSRRLIdleSec))*time.Second {
					delete(s.rrl, ip)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) allowIP(ip string) bool {
	if !s.cfg.DNSRRLEnabled {
		return true
	}
	now := time.Now()
	rate := float64(max(1, s.cfg.DNSRRLRate))
	burst := float64(max(s.cfg.DNSRRLBurst, s.cfg.DNSRRLRate))
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.rrl[ip]
	if !ok {
		b = &tokenBucket{tokens: burst, last: now, lastSeen: now}
		s.rrl[ip] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
	b.lastSeen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (s *Server) refusalCode() int {
	if s.cfg.DNSAbuseRcode == "SERVFAIL" {
		return mdns.RcodeServerFailure
	}
	return mdns.RcodeRefused
}

func parseRemoteHost(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return host
	}
	return addr.String()
}

func (s *Server) handle(w mdns.ResponseWriter, r *mdns.Msg) {
	start := time.Now()
	proto := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		proto = "tcp"
	}
	defer s.dnsLatency.WithLabelValues(proto).Observe(time.Since(start).Seconds())

	m := new(mdns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Compress = true
	if o := r.IsEdns0(); o != nil {
		m.SetEdns0(uint16(s.cfg.DNSMaxUDPSize), true)
	}
	if len(r.Question) == 0 {
		s.dnsRcodes.WithLabelValues(mdns.RcodeToString[m.Rcode]).Inc()
		_ = w.WriteMsg(m)
		return
	}
	host := parseRemoteHost(w.RemoteAddr())
	if !s.allowIP(host) {
		m.Rcode = s.refusalCode()
		s.dnsRcodes.WithLabelValues(mdns.RcodeToString[m.Rcode]).Inc()
		_ = w.WriteMsg(m)
		return
	}
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		s.mu.Lock()
		if s.currentTCP.Load() >= int64(s.cfg.DNSMaxTCP) || s.tcpPerIP[host] >= s.cfg.DNSPerIPTCP {
			s.mu.Unlock()
			m.Rcode = mdns.RcodeRefused
			s.dnsRcodes.WithLabelValues(mdns.RcodeToString[m.Rcode]).Inc()
			_ = w.WriteMsg(m)
			return
		}
		s.currentTCP.Add(1)
		s.tcpPerIP[host]++
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			s.currentTCP.Add(-1)
			if s.tcpPerIP[host] <= 1 {
				delete(s.tcpPerIP, host)
			} else {
				s.tcpPerIP[host]--
			}
			s.mu.Unlock()
		}()
	}
	q := r.Question[0]
	s.dnsQtypes.WithLabelValues(mdns.TypeToString[q.Qtype]).Inc()
	if c, ok := s.queryCounts[q.Qtype]; ok {
		c.Add(1)
	}
	if q.Qclass == mdns.ClassCHAOS && strings.EqualFold(q.Name, "version.bind.") {
		m.Answer = []mdns.RR{&mdns.TXT{Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassCHAOS, Ttl: 0}, Txt: []string{s.cfg.ChaosVersion}}}
		s.dnsRcodes.WithLabelValues(mdns.RcodeToString[m.Rcode]).Inc()
		_ = w.WriteMsg(m)
		return
	}
	if q.Qtype == mdns.TypeAXFR || q.Qtype == mdns.TypeIXFR {
		m.Rcode = mdns.RcodeRefused
		s.dnsRcodes.WithLabelValues(mdns.RcodeToString[m.Rcode]).Inc()
		_ = w.WriteMsg(m)
		return
	}
	qName := validate.NormalizeDomain(q.Name)
	zones, err := s.allZones()
	if err != nil {
		slog.Error("dns allZones failed", "err", err)
		m.Rcode = mdns.RcodeServerFailure
		s.dnsRcodes.WithLabelValues(mdns.RcodeToString[m.Rcode]).Inc()
		_ = w.WriteMsg(m)
		return
	}
	zone := LongestZone(qName, zones)
	if zone == "" {
		m.Rcode = mdns.RcodeRefused
		s.dnsRcodes.WithLabelValues(mdns.RcodeToString[m.Rcode]).Inc()
		_ = w.WriteMsg(m)
		return
	}
	zoneID, soa, err := s.zoneInfo(zone)
	if err != nil {
		slog.Error("dns zoneInfo failed", "zone", zone, "err", err)
		m.Rcode = mdns.RcodeServerFailure
		s.dnsRcodes.WithLabelValues(mdns.RcodeToString[m.Rcode]).Inc()
		_ = w.WriteMsg(m)
		return
	}
	recs, err := s.lookup(zoneID, qName, q.Qtype, zone, host)
	if err != nil {
		slog.Error("dns lookup failed", "zone", zone, "qname", qName, "qtype", q.Qtype, "err", err)
		m.Rcode = mdns.RcodeServerFailure
		s.dnsRcodes.WithLabelValues(mdns.RcodeToString[m.Rcode]).Inc()
		_ = w.WriteMsg(m)
		return
	}
	if len(recs) == 0 {
		if !s.nameExists(zoneID, qName, zone) {
			m.Rcode = mdns.RcodeNameError
		}
		m.Ns = append(m.Ns, soa)
		s.dnsRcodes.WithLabelValues(mdns.RcodeToString[m.Rcode]).Inc()
		_ = w.WriteMsg(m)
		return
	}
	if q.Qtype == mdns.TypeANY {
		switch s.cfg.DNSAnyMode {
		case "refuse":
			m.Rcode = mdns.RcodeRefused
			s.dnsRcodes.WithLabelValues(mdns.RcodeToString[m.Rcode]).Inc()
			_ = w.WriteMsg(m)
			return
		case "single":
			recs = recs[:1]
		default:
			if len(recs) > max(1, s.cfg.DNSAnyLimit) {
				recs = recs[:max(1, s.cfg.DNSAnyLimit)]
			}
		}
	}
	m.Answer = fitAnswers(r, m, recs, s.cfg.DNSMaxUDPSize)
	if w.LocalAddr().Network() == "udp" && len(m.Answer) < len(recs) {
		m.Truncated = true
	}
	s.dnsRcodes.WithLabelValues(mdns.RcodeToString[m.Rcode]).Inc()
	_ = w.WriteMsg(m)
}

func fitAnswers(req, resp *mdns.Msg, recs []mdns.RR, maxUDP int) []mdns.RR {
	if maxUDP <= 0 {
		maxUDP = 1232
	}
	if req == nil || req.MsgHdr.Response || len(recs) == 0 {
		return recs
	}
	out := make([]mdns.RR, 0, len(recs))
	for _, rr := range recs {
		candidate := append(append([]mdns.RR{}, out...), rr)
		resp.Answer = candidate
		if resp.Len() > maxUDP {
			break
		}
		out = candidate
	}
	resp.Answer = out
	return out
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
		if err := rows.Scan(&z); err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Server) zoneInfo(domain string) (int64, mdns.RR, error) {
	var id int64
	var mname, rname string
	var serial int64
	var refresh, retry, expire, minimum int
	err := s.db.QueryRow(`SELECT id,soa_mname,soa_rname,soa_serial,soa_refresh,soa_retry,soa_expire,soa_minimum FROM zones WHERE domain=?`, domain).Scan(&id, &mname, &rname, &serial, &refresh, &retry, &expire, &minimum)
	if err != nil {
		return 0, nil, err
	}
	return id, &mdns.SOA{Hdr: mdns.RR_Header{Name: mdns.Fqdn(domain), Rrtype: mdns.TypeSOA, Class: mdns.ClassINET, Ttl: uint32(minimum)}, Ns: mdns.Fqdn(mname), Mbox: mdns.Fqdn(rname), Serial: uint32(serial), Refresh: uint32(refresh), Retry: uint32(retry), Expire: uint32(expire), Minttl: uint32(minimum)}, nil
}
func (s *Server) nameExists(zoneID int64, fqdn, zone string) bool {
	rel := "@"
	if fqdn != zone {
		rel = strings.TrimSuffix(strings.TrimSuffix(fqdn, "."+zone), ".")
	}
	var c int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM records WHERE zone_id=? AND enabled=1 AND (name=? OR name='*')`, zoneID, rel).Scan(&c); err != nil {
		slog.Error("dns nameExists failed", "zoneID", zoneID, "fqdn", fqdn, "err", err)
		return false
	}
	return c > 0
}
func (s *Server) lookup(zoneID int64, fqdn string, qt uint16, zone, remote string) ([]mdns.RR, error) {
	rel := "@"
	if fqdn != zone {
		rel = strings.TrimSuffix(strings.TrimSuffix(fqdn, "."+zone), ".")
	}
	rows, err := s.db.Query(`SELECT type,ttl,data_json,name FROM records WHERE zone_id=? AND enabled=1 AND (name=? OR name='*')`, zoneID, rel)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var exact, wildcard []mdns.RR
	haveCNAME := false
	for rows.Next() {
		var typ, data, recName string
		var ttl int
		if err := rows.Scan(&typ, &ttl, &data, &recName); err != nil {
			return nil, err
		}
		if qt != mdns.TypeANY && mdns.StringToType[typ] != qt {
			continue
		}
		if ttl < s.cfg.TTLMin || ttl > s.cfg.TTLMax {
			continue
		}
		h := mdns.RR_Header{Name: mdns.Fqdn(fqdn), Rrtype: mdns.StringToType[typ], Class: mdns.ClassINET, Ttl: uint32(ttl)}
		var p map[string]any
		if err := json.Unmarshal([]byte(data), &p); err != nil {
			slog.Warn("skipping malformed record json", "zoneID", zoneID, "fqdn", fqdn, "type", typ, "err", err)
			continue
		}
		var rr mdns.RR
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
			parsed := net.ParseIP(ip)
			if parsed == nil || parsed.To4() == nil {
				s.logInvalidIP("A", fqdn, ip)
				continue
			}
			rr = &mdns.A{Hdr: h, A: parsed.To4()}
		case "AAAA":
			ip, _ := p["ip"].(string)
			parsed := net.ParseIP(ip)
			if parsed == nil || parsed.To4() != nil {
				s.logInvalidIP("AAAA", fqdn, ip)
				continue
			}
			rr = &mdns.AAAA{Hdr: h, AAAA: parsed}
		case "TXT":
			vals := []string{}
			if arr, ok := p["texts"].([]any); ok {
				for _, v := range arr {
					if t, ok := v.(string); ok {
						vals = append(vals, t)
					}
				}
			}
			rr = &mdns.TXT{Hdr: h, Txt: vals}
		case "CNAME":
			target, _ := p["target"].(string)
			haveCNAME = true
			rr = &mdns.CNAME{Hdr: h, Target: mdns.Fqdn(target)}
		case "MX":
			exchange, _ := p["exchange"].(string)
			pref, _ := p["preference"].(float64)
			rr = &mdns.MX{Hdr: h, Mx: mdns.Fqdn(exchange), Preference: uint16(pref)}
		case "NS":
			host, _ := p["host"].(string)
			rr = &mdns.NS{Hdr: h, Ns: mdns.Fqdn(host)}
		case "SRV":
			target, _ := p["target"].(string)
			port, _ := p["port"].(float64)
			priority, _ := p["priority"].(float64)
			weight, _ := p["weight"].(float64)
			rr = &mdns.SRV{Hdr: h, Target: mdns.Fqdn(target), Port: uint16(port), Priority: uint16(priority), Weight: uint16(weight)}
		case "CAA":
			tag, _ := p["tag"].(string)
			value, _ := p["value"].(string)
			flags, _ := p["flags"].(float64)
			rr = &mdns.CAA{Hdr: h, Flag: uint8(flags), Tag: tag, Value: value}
		case "SOA":
			ns, _ := p["ns"].(string)
			mbox, _ := p["mbox"].(string)
			serial, _ := p["serial"].(float64)
			refresh, _ := p["refresh"].(float64)
			retry, _ := p["retry"].(float64)
			expire, _ := p["expire"].(float64)
			minttl, _ := p["minttl"].(float64)
			rr = &mdns.SOA{Hdr: h, Ns: mdns.Fqdn(ns), Mbox: mdns.Fqdn(mbox), Serial: uint32(serial), Refresh: uint32(refresh), Retry: uint32(retry), Expire: uint32(expire), Minttl: uint32(minttl)}
		}
		if rr == nil {
			continue
		}
		if recName == "*" {
			wildcard = append(wildcard, rr)
		} else {
			exact = append(exact, rr)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := exact
	if len(out) == 0 {
		out = wildcard
	}
	if haveCNAME {
		cn := []mdns.RR{}
		for _, rr := range out {
			if rr.Header().Rrtype == mdns.TypeCNAME {
				cn = append(cn, rr)
			}
		}
		return cn, nil
	}
	return out, nil
}

func (s *Server) logInvalidIP(recordType, fqdn, ip string) {
	now := time.Now().Unix()
	last := s.invalidLogTS.Load()
	if now-last < 5 {
		return
	}
	if s.invalidLogTS.CompareAndSwap(last, now) {
		slog.Warn("skipping invalid DNS record IP", "type", recordType, "fqdn", fqdn, "ip", ip)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
