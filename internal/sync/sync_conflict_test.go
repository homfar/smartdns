package sync

import (
	"path/filepath"
	"testing"

	"smartdns/internal/db"
)

func TestMergeSnapshotConflictSafe(t *testing.T) {
	d, _ := db.Open(filepath.Join(t.TempDir(), "app.db"))
	_ = db.Migrate(d)
	_, _ = d.Exec(`INSERT INTO zones(domain,enabled,soa_mname,soa_rname,soa_serial,soa_refresh,soa_retry,soa_expire,soa_minimum,created_at,updated_at,version) VALUES('example.com',1,'ns1.example.com','hostmaster.example.com',1,1,1,1,1,1,1,1)`)
	m := New(d, true, "", "tok", nil, "n1")
	if err := m.Merge([]byte(`{"node_id":"n2","sent_at":1,"nonce":"x","snapshot_hash":"bad","zones":[{"domain":"example.com","hash":"h"}]}`)); err != nil {
		t.Fatal(err)
	}
}
