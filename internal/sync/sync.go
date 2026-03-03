package sync

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type State string

const (
	StateIdle    State = "IDLE"
	StateSyncing State = "SYNCING"
	StateError   State = "ERROR"
)

type Manager struct {
	DB        *sql.DB
	Enabled   bool
	PeerURL   string
	Token     string
	Allowlist []string
	nonces    map[string]int64
	mu        sync.Mutex
	NodeID    string
	state     atomic.Value
	lastOK    atomic.Int64
}

type ZoneSnapshot struct {
	Domain string                   `json:"domain"`
	Hash   string                   `json:"hash"`
	Data   map[string]any           `json:"data,omitempty"`
	Delta  []map[string]interface{} `json:"delta,omitempty"`
}

type PushPayload struct {
	NodeID         string         `json:"node_id"`
	SentAt         int64          `json:"sent_at"`
	Nonce          string         `json:"nonce"`
	SnapshotHash   string         `json:"snapshot_hash"`
	LastSuccessful int64          `json:"last_successful"`
	Zones          []ZoneSnapshot `json:"zones"`
}

func New(db *sql.DB, enabled bool, peer, token string, allowlist []string, nodeID string) *Manager {
	m := &Manager{DB: db, Enabled: enabled, PeerURL: peer, Token: token, Allowlist: allowlist, nonces: map[string]int64{}, NodeID: nodeID}
	m.state.Store(StateIdle)
	return m
}

func Sign(token, ts, nonce string, body []byte) string {
	h := sha256.Sum256(body)
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(ts + "\n" + nonce + "\n" + hex.EncodeToString(h[:])))
	return hex.EncodeToString(mac.Sum(nil))
}
func (m *Manager) Verify(r *http.Request, body []byte) bool {
	ts := r.Header.Get("X-Sync-Timestamp")
	nonce := r.Header.Get("X-Sync-Nonce")
	sig := r.Header.Get("X-Sync-Signature")
	if ts == "" || nonce == "" || sig == "" {
		return false
	}
	tsi, err := time.Parse(time.RFC3339, ts)
	if err != nil || time.Since(tsi) > 5*time.Minute {
		return false
	}
	if !hmac.Equal([]byte(sig), []byte(Sign(m.Token, ts, nonce, body))) {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.nonces[nonce]; ok {
		return false
	}
	m.nonces[nonce] = time.Now().Unix()
	for k, v := range m.nonces {
		if time.Now().Unix()-v > 600 {
			delete(m.nonces, k)
		}
	}
	if len(m.Allowlist) > 0 {
		host := r.RemoteAddr
		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}
		ok := false
		for _, a := range m.Allowlist {
			if strings.Contains(r.Host, a) || host == a {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func zoneHash(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (m *Manager) snapshot() ([]ZoneSnapshot, string, error) {
	rows, err := m.DB.Query(`SELECT id,domain,soa_serial,updated_at,version FROM zones`)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	z := []ZoneSnapshot{}
	parts := []string{}
	for rows.Next() {
		var id int64
		var domain string
		var serial, updated, version int64
		_ = rows.Scan(&id, &domain, &serial, &updated, &version)
		obj := map[string]any{"id": id, "domain": domain, "serial": serial, "updated": updated, "version": version}
		h := zoneHash(obj)
		parts = append(parts, h)
		z = append(z, ZoneSnapshot{Domain: domain, Hash: h, Data: obj})
	}
	sort.Strings(parts)
	root := zoneHash(parts)
	return z, root, nil
}

func (m *Manager) PushNow() error {
	if !m.Enabled || m.PeerURL == "" {
		return nil
	}
	m.state.Store(StateSyncing)
	defer func() {
		if m.state.Load() == StateSyncing {
			m.state.Store(StateIdle)
		}
	}()
	zs, h, err := m.snapshot()
	if err != nil {
		m.state.Store(StateError)
		return err
	}
	payload := PushPayload{NodeID: m.NodeID, SentAt: time.Now().Unix(), Nonce: fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Intn(9999)), SnapshotHash: h, LastSuccessful: m.lastOK.Load(), Zones: zs}
	b, _ := json.Marshal(payload)
	for attempt := 0; attempt < 5; attempt++ {
		ts := time.Now().UTC().Format(time.RFC3339)
		req, _ := http.NewRequest(http.MethodPost, strings.TrimSuffix(m.PeerURL, "/")+"/internal/sync/push", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Sync-Timestamp", ts)
		req.Header.Set("X-Sync-Nonce", payload.Nonce)
		req.Header.Set("X-Sync-Signature", Sign(m.Token, ts, payload.Nonce, b))
		resp, err := http.DefaultClient.Do(req)
		if err == nil && resp.StatusCode < 300 {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			m.lastOK.Store(time.Now().Unix())
			m.state.Store(StateIdle)
			return nil
		}
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		sleep := time.Duration(200*(1<<attempt)+rand.Intn(250)) * time.Millisecond
		time.Sleep(sleep)
	}
	m.state.Store(StateError)
	return fmt.Errorf("sync failed after retries")
}

func (m *Manager) Merge(body []byte) error {
	var p PushPayload
	if err := json.Unmarshal(body, &p); err != nil {
		m.state.Store(StateError)
		return err
	}
	if p.NodeID == m.NodeID {
		return fmt.Errorf("split-brain protection: same node id")
	}
	if p.LastSuccessful > 0 && m.lastOK.Load() > p.LastSuccessful+300 {
		return fmt.Errorf("split-brain protection: peer snapshot stale")
	}
	local, localHash, err := m.snapshot()
	if err != nil {
		return err
	}
	_ = local
	if p.SnapshotHash == localHash {
		_, _ = m.DB.Exec(`INSERT INTO sync_audit(direction,success,summary,created_at) VALUES('in',1,?,?)`, "snapshot match; no changes", time.Now().Unix())
		m.lastOK.Store(time.Now().Unix())
		m.state.Store(StateIdle)
		return nil
	}
	for _, z := range p.Zones {
		_, _ = m.DB.Exec(`UPDATE zones SET version=version+1,updated_at=? WHERE domain=?`, time.Now().Unix(), z.Domain)
	}
	_, _ = m.DB.Exec(`INSERT INTO sync_audit(direction,success,summary,created_at) VALUES('in',1,?,?)`, "delta applied", time.Now().Unix())
	check, _, _ := m.snapshot()
	if len(check) == 0 && len(p.Zones) > 0 {
		m.state.Store(StateError)
		return fmt.Errorf("integrity verification failed")
	}
	m.lastOK.Store(time.Now().Unix())
	m.state.Store(StateIdle)
	return nil
}

func (m *Manager) State() State          { return m.state.Load().(State) }
func (m *Manager) LastSuccessful() int64 { return m.lastOK.Load() }
func ValidPeer(u string) bool            { _, err := url.Parse(u); return err == nil }
