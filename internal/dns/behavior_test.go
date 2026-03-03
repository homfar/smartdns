package dns

import (
	"path/filepath"
	"testing"

	mdns "github.com/miekg/dns"
	"log/slog"
	"smartdns/internal/config"
	"smartdns/internal/db"
	"smartdns/internal/geo"
)

func setupDNSTest(t *testing.T) *Server {
	t.Helper()
	d, _ := db.Open(filepath.Join(t.TempDir(), "app.db"))
	_ = db.Migrate(d)
	_, _ = d.Exec(`INSERT INTO zones(id,domain,enabled,soa_mname,soa_rname,soa_serial,soa_refresh,soa_retry,soa_expire,soa_minimum,created_at,updated_at,version) VALUES(1,'example.com',1,'ns1.example.com.','hostmaster.example.com.',1,3600,600,1209600,300,1,1,1)`)
	cfg := config.Load()
	cfg.TTLMin = 1
	cfg.TTLMax = 86400
	cfg.DNSMaxUDPSize = 80
	cfg.DNSAnyMode = "minimal"
	cfg.DNSAnyLimit = 2
	return New(d, geo.NewMMDB("/no", slog.Default()), cfg)
}

func TestWildcardExactPrecedence(t *testing.T) {
	s := setupDNSTest(t)
	_, _ = s.db.Exec(`INSERT INTO records(zone_id,name,type,ttl,enabled,data_json,created_at,updated_at,version) VALUES(1,'*','A',60,1,'{"mode":"SINGLE","ip":"1.1.1.1"}',1,1,1)`)
	_, _ = s.db.Exec(`INSERT INTO records(zone_id,name,type,ttl,enabled,data_json,created_at,updated_at,version) VALUES(1,'www','A',60,1,'{"mode":"SINGLE","ip":"2.2.2.2"}',1,1,1)`)
	rrs := s.lookup(1, "www.example.com", mdns.TypeA, "example.com", "8.8.8.8")
	if len(rrs) != 1 || rrs[0].(*mdns.A).A.String() != "2.2.2.2" {
		t.Fatalf("expected exact record, got %#v", rrs)
	}
}

func TestAnyModeMinimalCap(t *testing.T) {
	s := setupDNSTest(t)
	_, _ = s.db.Exec(`INSERT INTO records(zone_id,name,type,ttl,enabled,data_json,created_at,updated_at,version) VALUES(1,'@','A',60,1,'{"mode":"SINGLE","ip":"1.1.1.1"}',1,1,1)`)
	_, _ = s.db.Exec(`INSERT INTO records(zone_id,name,type,ttl,enabled,data_json,created_at,updated_at,version) VALUES(1,'@','AAAA',60,1,'{"ip":"2001:db8::1"}',1,1,1)`)
	_, _ = s.db.Exec(`INSERT INTO records(zone_id,name,type,ttl,enabled,data_json,created_at,updated_at,version) VALUES(1,'@','TXT',60,1,'{"texts":["x"]}',1,1,1)`)
	rrs := s.lookup(1, "example.com", mdns.TypeANY, "example.com", "8.8.8.8")
	if len(rrs) < 3 {
		t.Fatalf("expected all records from lookup before cap")
	}
	m := new(mdns.Msg)
	q := new(mdns.Msg)
	q.SetQuestion("example.com.", mdns.TypeANY)
	m.SetReply(q)
	ans := fitAnswers(q, m, rrs[:2], 512)
	if len(ans) == 0 {
		t.Fatal("expected at least one any response")
	}
}

func TestFitAnswersTruncation(t *testing.T) {
	q := new(mdns.Msg)
	q.SetQuestion("example.com.", mdns.TypeTXT)
	m := new(mdns.Msg)
	m.SetReply(q)
	rrs := []mdns.RR{}
	for i := 0; i < 6; i++ {
		rrs = append(rrs, &mdns.TXT{Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 60}, Txt: []string{"01234567890123456789"}})
	}
	ans := fitAnswers(q, m, rrs, 120)
	if len(ans) == 0 || len(ans) >= len(rrs) {
		t.Fatalf("expected partial packing, got %d", len(ans))
	}
}
