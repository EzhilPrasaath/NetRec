# NetRec

A small OpenVAS-inspired network scanner: discover hosts, open ports, services and OS with nmap, correlate
detected service versions with CVEs from the NIST NVD, view the results with charts, download a PDF report.

**Honest scope:** NetRec infers exposure from version banners (CPE -> NVD). OpenVAS actively tests for
vulnerabilities; NetRec does not. Findings are *potential exposure*, not confirmed exploitability.

## Legal and ethical use
Only scan systems you own or have written permission to test. Unauthorised scanning can be a criminal
offence (in India, see IT Act 2000 s.43 and s.66; most countries have equivalents). The UI requires an
authorisation tick-box and every scan stores that attestation, your account and your IP.
Safe practice targets: your own lab/VMs, your home network, and `scanme.nmap.org` (published by the Nmap
project for testing, keep it light: Fast profile).

## Quick start
Requires Docker with Compose v2.

```bash
cd netrec
cp .env.example .env
python3 -c "import secrets;print(secrets.token_hex(32))"   # paste into SECRET_KEY
# set DB_PASSWORD (letters/digits only). Optional: NVD_API_KEY
docker compose up -d --build
```
Open http://localhost:8000, register, scan. Logs: `docker compose logs -f web`. Stop: `docker compose down`
(add `-v` to also wipe the database).

The database and tables are created automatically on first start. Passwords are hashed with scrypt (per-user salt).

## Using it
1. **Target**: single IP, CIDR up to /24, or a public hostname. Loopback and link-local are blocked.
2. **Profile**: Fast (top 100 ports, light version probing), Moderate (top 1000 + OS + versions), Deep (all 65535 ports, full version probing).
3. **Ports**: leave blank for the profile default, or `22,80,443`, `1-1024`, `22,8000-8100`, `all`.
4. **Time limit**: hard cap in minutes. When reached, nmap is interrupted and partial results are kept and flagged.
5. Watch live progress (cancel any time). Results show tiles, a severity donut, top ports, OS mix, and per-host details.
6. Click **PDF report** to download.

Tick "Treat hosts as online" for internet targets that drop ping, otherwise nmap may report them as down.

## Scanning your LAN
Default (bridge network) reaches LAN IPs through Docker's NAT: ports, services, OS detection work; MAC
addresses and ARP discovery do not. On **Linux** you can get full LAN visibility:
`docker compose -f docker-compose.yml -f docker-compose.host.yml up -d --build`
(Docker Desktop on Windows/macOS does not support true host networking.) Find your subnet with
`ip a` / `ipconfig` and scan e.g. `192.168.1.0/24`.

## Scanning Docker targets (Metasploitable etc.)
Containers on a different Docker network are unreachable from NetRec (Docker isolates bridges). Put both on a
shared network with `docker-compose.lab.yml` (see the file header), then scan the target's IP on that network.
A host with 0 open ports usually means unreachable or firewalled, not clean.

## NVD rate limits
Without an API key NVD allows ~5 requests / 30 s, so each *distinct* service costs ~6.5 s. Results are cached
7 days in Postgres. A free key (https://nvd.nist.gov/developers/request-an-api-key) makes it ~10x faster.
The CVE phase has a 4 minute budget (`CVE_BUDGET_SEC`); if hit, the report says so.

## Layout
```
netrec/
├── docker-compose.yml        web + postgres, ports bound to localhost
├── docker-compose.host.yml   optional Linux host-network override
├── Dockerfile                python + nmap (file capabilities, non-root user)
├── .env.example  requirements.txt  wsgi.py
└── app/
    ├── __init__.py   app factory, DB auto-create with retry, security headers, CSRF guard
    ├── config.py     env config and limits
    ├── models.py     User, Scan, CVECache
    ├── auth.py       register / login / logout, scrypt hashing, login throttling
    ├── validators.py target + port parsing (blocks option injection)
    ├── scanner.py    nmap command builder, progress streaming, XML parser
    ├── cve.py        NVD API 2.0 client, rate limit, cache
    ├── scans.py      scan API, background job, summary, PDF endpoint
    ├── report.py     PDF generation (reportlab)
    └── static/       index.html, style.css, app.js
```

## Troubleshooting
- `OS: unknown` everywhere: raw sockets unavailable. Confirm `cap_add: NET_RAW` is in compose; try Moderate/Deep on a host with open AND closed ports.
- Host shows as down: tick "Treat hosts as online".
- CVE lookup slow: add `NVD_API_KEY`.
- Changed `.env` password after first run: `docker compose down -v` (wipes data) then up again.

## Known limits (by design, for a demo)
IPv4 only. One gunicorn worker runs scan threads in-process, so a restart marks running scans
failed. No OS-level CVE matching, no authenticated scans, no active exploit checks. Upgrade path: move jobs to a
queue (RQ/Celery), add NSE `vulners`/`vuln` scripts, add tests and CI.
