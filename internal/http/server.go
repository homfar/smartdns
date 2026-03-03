package http

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/bcrypt"
	"smartdns/internal/config"
	"smartdns/internal/geo"
	syncmod "smartdns/internal/sync"
	"smartdns/internal/validate"
)

//go:embed templates/*.html
var tplFS embed.FS

type Server struct {
	cfg      config.Config
	db       *sql.DB
	geo      geo.Provider
	sync     *syncmod.Manager
	t        *template.Template
	logger   *slog.Logger
	sessions map[string]string
	csrf     map[string]string
	mu       sync.Mutex
	rateMu   sync.Mutex
	rate     map[string]rateBucket
	auditSeq atomic.Uint64
}

type rateBucket struct {
	Count int
	At    time.Time
}

func New(cfg config.Config, db *sql.DB, gp geo.Provider, sm *syncmod.Manager, logger *slog.Logger) *Server {
	t := template.Must(template.ParseFS(tplFS, "templates/*.html"))
	return &Server{cfg: cfg, db: db, geo: gp, sync: sm, t: t, logger: logger, sessions: map[string]string{}, csrf: map[string]string{}, rate: map[string]rateBucket{}}
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(s.secHeaders)
	r.Use(s.globalRate)
	r.Handle("/metrics", promhttp.Handler())
	r.Get("/healthz", s.healthz)
	r.Get("/readyz", s.readyz)
	r.Get("/login", s.loginPage)
	r.Post("/login", s.loginPost)
	r.Post("/logout", s.authed(s.logout))
	r.Group(func(ar chi.Router) {
		ar.Use(s.authMW)
		ar.Get("/", s.dashboard)
		ar.Get("/zones", s.zonesList)
		ar.Post("/zones", s.zoneCreate)
		ar.Post("/zones/{id}/toggle", s.zoneToggle)
		ar.Post("/zones/{id}/records", s.recordCreate)
		ar.Post("/records/{id}/delete", s.recordDelete)
		ar.Post("/sync/now", s.syncNow)
		ar.Get("/settings", s.settingsPage)
		ar.Post("/settings", s.settingsSave)
	})
	r.Post("/internal/sync/push", s.syncPush)
	return r
}
func (s *Server) secHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
func (s *Server) globalRate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.RemoteAddr
		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}
		s.rateMu.Lock()
		b := s.rate[host]
		if time.Since(b.At) > time.Minute {
			b = rateBucket{At: time.Now()}
		}
		b.Count++
		s.rate[host] = b
		s.rateMu.Unlock()
		if b.Count > s.cfg.APIRatePerMin {
			http.Error(w, "rate limited", 429)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) adminAllowed(remote string) bool {
	if len(s.cfg.AdminAllowlist) == 0 {
		return true
	}
	h := remote
	if strings.Contains(h, ":") {
		h = strings.Split(h, ":")[0]
	}
	for _, allowed := range s.cfg.AdminAllowlist {
		if ap, err := netip.ParseAddr(allowed); err == nil {
			if hp, err := netip.ParseAddr(h); err == nil && hp == ap {
				return true
			}
		}
		if h == allowed {
			return true
		}
	}
	return false
}
func (s *Server) render(w http.ResponseWriter, n string, d any) { _ = s.t.ExecuteTemplate(w, n, d) }
func (s *Server) rand() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
func (s *Server) setSession(w http.ResponseWriter, u string) {
	sid := s.rand()
	csrf := s.rand()
	s.mu.Lock()
	s.sessions[sid] = u
	s.csrf[sid] = csrf
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
}
func (s *Server) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminAllowed(r.RemoteAddr) {
			http.Error(w, "forbidden", 403)
			return
		}
		c, err := r.Cookie("sid")
		if err != nil || s.sessions[c.Value] == "" {
			http.Redirect(w, r, "/login", 302)
			return
		}
		if r.Method == http.MethodPost && !strings.HasPrefix(r.URL.Path, "/internal/") {
			if c.Value == "" || s.csrf[c.Value] == "" {
				http.Error(w, "csrf", 403)
				return
			}
			if r.FormValue("csrf") != s.csrf[c.Value] {
				http.Error(w, "csrf", 403)
				return
			}
		}
		next(w, r)
	}
}
func (s *Server) authMW(next http.Handler) http.Handler {
	return s.authed(func(w http.ResponseWriter, r *http.Request) { next.ServeHTTP(w, r) })
}
func (s *Server) loginPage(w http.ResponseWriter, _ *http.Request) { s.render(w, "login.html", nil) }
func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	u, p := r.FormValue("username"), r.FormValue("password")
	var hash string
	_ = s.db.QueryRow(`SELECT password_hash FROM users WHERE username=?`, u).Scan(&hash)
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(p)) != nil {
		http.Error(w, "invalid", 401)
		return
	}
	if c, err := bcrypt.Cost([]byte(hash)); err == nil && c < bcrypt.DefaultCost {
		if nh, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost); err == nil {
			_, _ = s.db.Exec(`UPDATE users SET password_hash=? WHERE username=?`, string(nh), u)
		}
	}
	s.setSession(w, u)
	http.Redirect(w, r, "/", 302)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("sid")
	s.mu.Lock()
	delete(s.sessions, c.Value)
	delete(s.csrf, c.Value)
	s.mu.Unlock()
	http.Redirect(w, r, "/login", 302)
}
func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("sid")
	s.render(w, "dashboard.html", map[string]any{"MMDB": s.geo.Healthy(), "Sync": s.sync.Enabled, "CSRF": s.csrf[c.Value]})
}
func (s *Server) zonesList(w http.ResponseWriter, r *http.Request) {
	rows, _ := s.db.Query(`SELECT id,domain,enabled FROM zones ORDER BY domain`)
	defer rows.Close()
	type z struct {
		ID      int
		Domain  string
		Enabled int
	}
	var zs []z
	for rows.Next() {
		var x z
		_ = rows.Scan(&x.ID, &x.Domain, &x.Enabled)
		zs = append(zs, x)
	}
	c, _ := r.Cookie("sid")
	s.render(w, "zones.html", map[string]any{"Zones": zs, "CSRF": s.csrf[c.Value]})
}
func (s *Server) zoneCreate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	d := validate.NormalizeDomain(r.FormValue("domain"))
	if err := validate.FQDN(d); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	now := time.Now().Unix()
	_, _ = s.db.Exec(`INSERT INTO zones(domain,enabled,soa_mname,soa_rname,soa_serial,soa_refresh,soa_retry,soa_expire,soa_minimum,created_at,updated_at,version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, d, 1, r.FormValue("soa_mname"), r.FormValue("soa_rname"), now, 3600, 600, 1209600, 300, now, now, 1)
	_, _ = s.db.Exec(`INSERT INTO audit_log(event_type,subject,details,created_at) VALUES('zone_change',?, ?,?)`, d, "created", now)
	http.Redirect(w, r, "/zones", 302)
}
func (s *Server) zoneToggle(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	now := time.Now().Unix()
	_, _ = s.db.Exec(`UPDATE zones SET enabled=CASE WHEN enabled=1 THEN 0 ELSE 1 END,updated_at=?,version=version+1,soa_serial=CASE WHEN soa_serial<? THEN ? ELSE soa_serial+1 END WHERE id=?`, now, now, now, id)
	_, _ = s.db.Exec(`INSERT INTO audit_log(event_type,subject,details,created_at) VALUES('zone_change',?, ?,?)`, id, "toggle", time.Now().Unix())
	http.Redirect(w, r, "/zones", 302)
}
func (s *Server) recordCreate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	zid := chi.URLParam(r, "id")
	typ := r.FormValue("type")
	data := r.FormValue("data_json")
	ttl := 300
	if tv := r.FormValue("ttl"); tv != "" {
		if n, err := strconv.Atoi(tv); err == nil {
			ttl = n
		}
	}
	if typ == "A" {
		if err := validate.AData(data); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	}
	if err := validate.TTL(ttl, s.cfg.TTLMin, s.cfg.TTLMax); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if typ == "CNAME" {
		var c int
		_ = s.db.QueryRow(`SELECT COUNT(1) FROM records WHERE zone_id=? AND name=? AND enabled=1 AND type<>'CNAME'`, zid, r.FormValue("name")).Scan(&c)
		if c > 0 {
			http.Error(w, "cname exclusivity violation", 400)
			return
		}
	}
	_, _ = s.db.Exec(`INSERT INTO records(zone_id,name,type,ttl,enabled,data_json,created_at,updated_at,version) VALUES(?,?,?,?,?,?,?,?,?)`, zid, r.FormValue("name"), typ, ttl, 1, data, time.Now().Unix(), time.Now().Unix(), 1)
	now := time.Now().Unix()
	_, _ = s.db.Exec(`UPDATE zones SET updated_at=?,version=version+1,soa_serial=CASE WHEN soa_serial<? THEN ? ELSE soa_serial+1 END WHERE id=?`, now, now, now, zid)
	_, _ = s.db.Exec(`INSERT INTO audit_log(event_type,subject,details,created_at) VALUES('record_change',?, ?,?)`, zid, typ+":"+r.FormValue("name"), time.Now().Unix())
	http.Redirect(w, r, "/zones", 302)
}
func (s *Server) recordDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	_, _ = s.db.Exec(`DELETE FROM records WHERE id=?`, id)
	_, _ = s.db.Exec(`INSERT INTO audit_log(event_type,subject,details,created_at) VALUES('record_change',?, ?,?)`, id, "delete", time.Now().Unix())
	http.Redirect(w, r, "/zones", 302)
}
func (s *Server) syncNow(w http.ResponseWriter, r *http.Request) {
	if !s.sync.Enabled {
		http.Error(w, "disabled", 403)
		return
	}
	if err := s.sync.PushNow(); err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	http.Redirect(w, r, "/", 302)
}
func (s *Server) syncPush(w http.ResponseWriter, r *http.Request) {
	if !s.sync.Enabled {
		http.NotFound(w, r)
		return
	}
	b, _ := io.ReadAll(r.Body)
	if !s.sync.Verify(r, b) {
		http.Error(w, "forbidden", 403)
		return
	}
	if err := s.sync.Merge(b); err == nil {
		_, _ = s.db.Exec(`INSERT INTO audit_log(event_type,subject,details,created_at) VALUES('sync_event',?,?,?)`, "push", "merged", time.Now().Unix())
	}
	w.WriteHeader(204)
}
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	if err := s.db.QueryRow(`PRAGMA quick_check`).Scan(new(string)); err != nil {
		http.Error(w, "db locked", 503)
		return
	}
	if s.cfg.GEORequired && !s.geo.Healthy() {
		http.Error(w, "mmdb required", 503)
		return
	}
	w.Write([]byte("ok"))
}
func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("sid")
	s.render(w, "settings.html", map[string]any{"CSRF": s.csrf[c.Value]})
}
func (s *Server) settingsSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	_, _ = s.db.Exec(`INSERT INTO settings(key,value) VALUES('ns1',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, r.FormValue("ns1"))
	_, _ = s.db.Exec(`INSERT INTO settings(key,value) VALUES('ns2',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, r.FormValue("ns2"))
	http.Redirect(w, r, "/settings", 302)
}
func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	var one int
	dbOK := s.db.QueryRow(`SELECT 1`).Scan(&one) == nil && one == 1
	out := map[string]any{"db": dbOK, "mmdb": s.geo.Healthy(), "sync_state": s.sync.State(), "last_sync_ok": s.sync.LastSuccessful()}
	if !dbOK || (s.cfg.GEORequired && !s.geo.Healthy()) {
		w.WriteHeader(503)
	}
	b, _ := json.Marshal(out)
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}
