# SmartDNS GeoDNS

## English (0 to 100)
- Authoritative DNS on UDP/TCP 53 and admin on 5555.
- IR resolvers get `iran_ip`; others get `foreign_ip` for GEO A mode.
- If MMDB missing/unhealthy, GEO defaults to foreign IP.
- Run with Docker:
  1. `cp .env.example .env`
  2. Put `GeoLite2-Country.mmdb` in `./mmdb`
  3. `docker compose up -d --build`
- If Docker Hub is blocked in your network, set `GO_IMAGE` and `RUNTIME_IMAGE` in `.env` to reachable mirror images.
- Login `/login`, create zone, then records.
- Sync:
  - `NO_SYNC=true` disables sync and endpoint.
  - `NO_SYNC=false` enables periodic + manual sync (`/sync/now`).
- Production notes: reverse proxy TLS, firewall ports 53/5555, sqlite backups, run with least privilege/capabilities for low ports.
- Troubleshooting:
  - MMDB missing => dashboard shows false, GEO sends foreign.
  - Port 53 permission denied => add capabilities or run privileged.
  - NXDOMAIN/REFUSED follow authoritative-only behavior.
  - Resolver geo limitation applies.

## فارسی (۰ تا ۱۰۰)
- سرویس DNS authoritative روی پورت ۵۳ (TCP/UDP) و پنل ادمین روی ۵۵۵۵ اجرا می‌شود.
- اگر IP ریزالور از ایران باشد، در حالت GEO برای رکورد A مقدار `iran_ip` برمی‌گردد؛ در غیر این صورت `foreign_ip`.
- اگر فایل MMDB موجود نباشد یا خراب باشد، سرویس بالا می‌ماند و خروجی GEO به شکل امن روی IP خارجی می‌افتد.
- راه‌اندازی با داکر:
  ۱) `cp .env.example .env`
  ۲) فایل `GeoLite2-Country.mmdb` را داخل `./mmdb` قرار دهید.
  ۳) `docker compose up -d --build`
- اگر Docker Hub از سمت شبکه شما دردسترس نیست، در فایل `.env` مقدار `GO_IMAGE` و `RUNTIME_IMAGE` را روی رجیستری آینه تنظیم کنید (مثلاً آینه سازمانی/داخلی).
- وارد `/login` شوید، زون بسازید و رکورد اضافه کنید.
- همگام‌سازی:
  - با `NO_SYNC=true` همگام‌سازی غیرفعال است.
  - با `NO_SYNC=false` هم دوره‌ای و هم دکمه Sync now فعال می‌شود.
- نکات پروداکشن: TLS با reverse proxy، فایروال، بکاپ sqlite، اجرای امن با دسترسی حداقلی.
- عیب‌یابی: نبود MMDB، مشکل دسترسی پورت ۵۳، NXDOMAIN/REFUSED، محدودیت geo بر اساس resolver.

## Production Deployment Guide
- Run as non-root with `CAP_NET_BIND_SERVICE` or use high ports behind LB.
- Enable DNS hardening defaults:
  - `DNS_RRL_ENABLED=true`
  - `DNS_RRL_RATE=20`
  - `DNS_MAX_TCP=100`
  - `DNS_MAX_UDP_SIZE=1232`
- API hardening options:
  - `ADMIN_ALLOWLIST=10.0.0.10,10.0.0.11`
  - `API_RATE_PER_MIN=120`
  - `GEO_REQUIRED=true` in GEO-critical deployments.

### Reverse proxy (nginx)
```nginx
server {
  listen 443 ssl;
  server_name dns-admin.example.com;
  location / {
    proxy_pass http://127.0.0.1:5555;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Host $host;
  }
}
```

### systemd unit
```ini
[Unit]
Description=SmartDNS GeoDNS
After=network.target

[Service]
User=smartdns
Group=smartdns
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/geodns
Restart=always
Environment=DNS_RRL_ENABLED=true

[Install]
WantedBy=multi-user.target
```

### Firewall rules example
- Allow: `53/udp`, `53/tcp`, `5555/tcp` (admin restricted source only).
- Deny all other inbound by default.

### Kernel tuning recommendations
- `net.core.rmem_max=8388608`
- `net.core.wmem_max=8388608`
- `net.ipv4.udp_mem=8388608 12582912 16777216`
- `net.ipv4.tcp_syncookies=1`

### Benchmark + load test
- Install `dnsperf`.
- Run `scripts/load_test.sh 127.0.0.1 53`.

### Backup & restore
- Auto-backup uses `DB_BACKUP_SEC` and creates timestamped `.bak` files beside DB.
- Restore: stop service, copy desired `.bak` to DB path, start service.

### Disaster recovery
1. Stop writes (maintenance mode).
2. Restore latest consistent DB backup.
3. Validate with `PRAGMA integrity_check`.
4. Resume and force `/sync/now` from primary.

### MMDB update procedure
1. Replace MMDB file atomically.
2. Service hot-reloads in background (10s poll).
3. Verify `/readyz` includes `"mmdb":true`.
