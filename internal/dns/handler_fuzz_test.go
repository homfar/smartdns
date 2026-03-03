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

type fuzzWriter struct{}

func (f *fuzzWriter) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero, Port: 53} }
func (f *fuzzWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53000}
}
func (f *fuzzWriter) WriteMsg(*mdns.Msg) error  { return nil }
func (f *fuzzWriter) Write([]byte) (int, error) { return 0, nil }
func (f *fuzzWriter) Close() error              { return nil }
func (f *fuzzWriter) TsigStatus() error         { return nil }
func (f *fuzzWriter) TsigTimersOnly(bool)       {}
func (f *fuzzWriter) Hijack()                   {}

func FuzzHandleMessageSafety(f *testing.F) {
	f.Add([]byte{0, 1, 0, 0})
	d, _ := db.Open(filepath.Join(f.TempDir(), "app.db"))
	_ = db.Migrate(d)
	_, _ = d.Exec(`INSERT INTO zones(id,domain,enabled,soa_mname,soa_rname,soa_serial,soa_refresh,soa_retry,soa_expire,soa_minimum,created_at,updated_at,version) VALUES(1,'example.com',1,'ns1.example.com.','hostmaster.example.com.',1,3600,600,1209600,300,1,1,1)`)
	cfg := config.Load()
	s := New(d, geo.NewMMDB("", slog.Default()), cfg)
	w := &fuzzWriter{}
	f.Fuzz(func(t *testing.T, in []byte) {
		m := new(mdns.Msg)
		if err := m.Unpack(in); err == nil {
			s.handle(w, m)
		}
	})
}
