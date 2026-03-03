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
