package sync

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
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
}

type PushPayload struct {
	NodeID string           `json:"node_id"`
	SentAt int64            `json:"sent_at"`
	Nonce  string           `json:"nonce"`
	Zones  []map[string]any `json:"zones"`
}

func New(db *sql.DB, enabled bool, peer, token string, allowlist []string, nodeID string) *Manager {
	return &Manager{DB: db, Enabled: enabled, PeerURL: peer, Token: token, Allowlist: allowlist, nonces: map[string]int64{}, NodeID: nodeID}
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

func (m *Manager) PushNow() error {
	if !m.Enabled || m.PeerURL == "" {
		return nil
	}
	payload := PushPayload{NodeID: m.NodeID, SentAt: time.Now().Unix(), Nonce: time.Now().Format("20060102150405")}
	b, _ := json.Marshal(payload)
	ts := time.Now().UTC().Format(time.RFC3339)
	req, _ := http.NewRequest(http.MethodPost, strings.TrimSuffix(m.PeerURL, "/")+"/internal/sync/push", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sync-Timestamp", ts)
	req.Header.Set("X-Sync-Nonce", payload.Nonce)
	req.Header.Set("X-Sync-Signature", Sign(m.Token, ts, payload.Nonce, b))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

func (m *Manager) Merge(body []byte) error {
	_, err := m.DB.Exec(`INSERT INTO sync_audit(direction,success,summary,created_at) VALUES('in',1,?,?)`, "sync received", time.Now().Unix())
	_ = body
	return err
}
func ValidPeer(u string) bool { _, err := url.Parse(u); return err == nil }
