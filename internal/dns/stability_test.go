package dns

import (
	"net"
	"path/filepath"
	"testing"

	mdns "github.com/miekg/dns"
	"log/slog"
	"smartdns/internal/config"
	"smartdns/internal/db"
	"smartdns/internal/geo"
)

type captureWriter struct{ msg *mdns.Msg }

func (w *captureWriter) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero, Port: 53} }
func (w *captureWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53000}
}
func (w *captureWriter) WriteMsg(m *mdns.Msg) error {
	w.msg = m.Copy()
	return nil
}
func (w *captureWriter) Write([]byte) (int, error) { return 0, nil }
func (w *captureWriter) Close() error              { return nil }
func (w *captureWriter) TsigStatus() error         { return nil }
func (w *captureWriter) TsigTimersOnly(bool)       {}
func (w *captureWriter) Hijack()                   {}

func setupServerForHandle(t *testing.T) *Server {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec(`INSERT INTO zones(id,domain,enabled,soa_mname,soa_rname,soa_serial,soa_refresh,soa_retry,soa_expire,soa_minimum,created_at,updated_at,version) VALUES(1,'example.com',1,'ns1.example.com.','hostmaster.example.com.',1,3600,600,1209600,300,1,1,1)`)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Load()
	cfg.TTLMin = 1
	cfg.TTLMax = 86400
	cfg.DNSMaxUDPSize = 120
	cfg.DNSRRLEnabled = false
	return New(d, geo.NewMMDB("/no", slog.Default()), cfg)
}

func TestNXDOMAINIncludesSOA(t *testing.T) {
	s := setupServerForHandle(t)
	w := &captureWriter{}
	req := new(mdns.Msg)
	req.SetQuestion("missing.example.com.", mdns.TypeA)
	s.handle(w, req)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Rcode != mdns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %d", w.msg.Rcode)
	}
	if len(w.msg.Ns) == 0 || w.msg.Ns[0].Header().Rrtype != mdns.TypeSOA {
		t.Fatal("expected SOA in authority section")
	}
}

func TestNODATAIncludesSOA(t *testing.T) {
	s := setupServerForHandle(t)
	_, err := s.db.Exec(`INSERT INTO records(zone_id,name,type,ttl,enabled,data_json,created_at,updated_at,version) VALUES(1,'www','A',60,1,'{"mode":"SINGLE","ip":"1.2.3.4"}',1,1,1)`)
	if err != nil {
		t.Fatal(err)
	}
	w := &captureWriter{}
	req := new(mdns.Msg)
	req.SetQuestion("www.example.com.", mdns.TypeAAAA)
	s.handle(w, req)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Rcode != mdns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %d", w.msg.Rcode)
	}
	if len(w.msg.Ns) == 0 || w.msg.Ns[0].Header().Rrtype != mdns.TypeSOA {
		t.Fatal("expected SOA in authority section")
	}
}

func TestHandleTruncatesUDPResponse(t *testing.T) {
	s := setupServerForHandle(t)
	for i := 0; i < 8; i++ {
		_, err := s.db.Exec(`INSERT INTO records(zone_id,name,type,ttl,enabled,data_json,created_at,updated_at,version) VALUES(1,'@','TXT',60,1,'{"texts":["abcdefghijklmnopqrstuvwxyz0123456789"]}',1,1,1)`)
		if err != nil {
			t.Fatal(err)
		}
	}
	w := &captureWriter{}
	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeTXT)
	s.handle(w, req)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if !w.msg.Truncated {
		t.Fatal("expected truncated response")
	}
	if len(w.msg.Answer) == 0 || len(w.msg.Answer) >= 8 {
		t.Fatalf("expected partial answers, got %d", len(w.msg.Answer))
	}
}

func TestLookupSkipsInvalidRecords(t *testing.T) {
	s := setupServerForHandle(t)
	_, err := s.db.Exec(`INSERT INTO records(zone_id,name,type,ttl,enabled,data_json,created_at,updated_at,version) VALUES(1,'@','A',60,1,'{"mode":"SINGLE","ip":"not-an-ip"}',1,1,1)`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec(`INSERT INTO records(zone_id,name,type,ttl,enabled,data_json,created_at,updated_at,version) VALUES(1,'@','A',60,1,'not-json',1,1,1)`)
	if err != nil {
		t.Fatal(err)
	}
	rrs, err := s.lookup(1, "example.com", mdns.TypeA, "example.com", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rrs) != 0 {
		t.Fatalf("expected invalid records to be skipped, got %d", len(rrs))
	}
}

func TestLookupQueryErrorNoPanic(t *testing.T) {
	s := setupServerForHandle(t)
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	rrs, err := s.lookup(1, "example.com", mdns.TypeA, "example.com", "1.1.1.1")
	if err == nil {
		t.Fatal("expected query error")
	}
	if len(rrs) != 0 {
		t.Fatal("expected no records on query error")
	}
}
