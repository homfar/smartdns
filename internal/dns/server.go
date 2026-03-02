package dns

import (
	"database/sql"
	"encoding/json"
	"net"
	"strings"

	mdns "github.com/miekg/dns"
	"smartdns/internal/geo"
)

type Server struct {
	db   *sql.DB
	geo  geo.Provider
	addr string
	udp  *mdns.Server
	tcp  *mdns.Server
}

func New(db *sql.DB, gp geo.Provider, addr string) *Server {
	return &Server{db: db, geo: gp, addr: addr}
}
func (s *Server) Start() error {
	h := mdns.HandlerFunc(s.handle)
	s.udp = &mdns.Server{Addr: s.addr, Net: "udp", Handler: h}
	s.tcp = &mdns.Server{Addr: s.addr, Net: "tcp", Handler: h}
	go s.udp.ListenAndServe()
	go s.tcp.ListenAndServe()
	return nil
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

func (s *Server) handle(w mdns.ResponseWriter, r *mdns.Msg) {
	m := new(mdns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	if len(r.Question) == 0 {
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	qName := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	zones, _ := s.allZones()
	zone := LongestZone(qName, zones)
	if zone == "" {
		m.Rcode = mdns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	zoneID, soa := s.zoneInfo(zone)
	recs := s.lookup(zoneID, qName, q.Qtype, zone, w.RemoteAddr().String())
	if len(recs) == 0 {
		if !s.nameExists(zoneID, qName, zone) {
			m.Rcode = mdns.RcodeNameError
		}
		m.Ns = append(m.Ns, soa)
		_ = w.WriteMsg(m)
		return
	}
	m.Answer = recs
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
	rows, _ := s.db.Query(`SELECT type,ttl,data_json FROM records WHERE zone_id=? AND enabled=1 AND (name=? OR name='*')`, zoneID, rel)
	defer rows.Close()
	var out []mdns.RR
	for rows.Next() {
		var typ, data string
		var ttl int
		_ = rows.Scan(&typ, &ttl, &data)
		if qt != mdns.TypeANY && mdns.StringToType[typ] != qt {
			continue
		}
		h := mdns.RR_Header{Name: mdns.Fqdn(fqdn), Rrtype: mdns.StringToType[typ], Class: mdns.ClassINET, Ttl: uint32(ttl)}
		var p map[string]any
		_ = json.Unmarshal([]byte(data), &p)
		switch typ {
		case "A":
			ip := ""
			if p["mode"] == "GEO" {
				host, _, _ := net.SplitHostPort(remote)
				iran, _ := p["iran_ip"].(string)
				foreign, _ := p["foreign_ip"].(string)
				ip = geo.SelectA(s.geo.CountryCode(net.ParseIP(host)), iran, foreign)
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
	return out
}
