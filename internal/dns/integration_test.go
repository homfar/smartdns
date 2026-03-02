package dns

import (
	"path/filepath"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"log/slog"
	"smartdns/internal/db"
	"smartdns/internal/geo"
)

func TestDNSQuery(t *testing.T) {
	d, _ := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	_, _ = d.Exec(`INSERT INTO zones(id,domain,enabled,soa_mname,soa_rname,soa_serial,soa_refresh,soa_retry,soa_expire,soa_minimum,created_at,updated_at,version) VALUES(1,'example.com',1,'ns1.example.com.','hostmaster.example.com.',1,3600,600,1209600,300,1,1,1)`)
	_, _ = d.Exec(`INSERT INTO records(zone_id,name,type,ttl,enabled,data_json,created_at,updated_at,version) VALUES(1,'@','A',60,1,'{"mode":"SINGLE","ip":"1.2.3.4"}',1,1,1)`)
	s := New(d, geo.NewMMDB("/no", slog.Default()), ":1053")
	_ = s.Start()
	time.Sleep(100 * time.Millisecond)
	c := new(mdns.Client)
	m := new(mdns.Msg)
	m.SetQuestion("example.com.", mdns.TypeA)
	r, _, err := c.Exchange(m, "127.0.0.1:1053")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Answer) == 0 {
		t.Fatal("no answer")
	}
}
