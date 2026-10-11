# NetRec

**A containerised, OpenVAS-inspired network exposure scanner.** NetRec discovers hosts, open ports, services and
operating systems with nmap, correlates detected service versions with CVEs from the NIST National Vulnerability
Database (NVD), shows live progress and charts in a web UI, and exports a formatted PDF report.

> **Scope in one sentence:** NetRec performs *version-based exposure detection*. It does not actively test or exploit
> vulnerabilities the way OpenVAS does. See [OpenVAS comparison](#openvas-comparison).

---

## Legal and ethical use

Only scan systems you own or have **written permission** to test. Unauthorised scanning can be a criminal offence
(in India see IT Act 2000 s.43 and s.66; most countries have equivalents).

NetRec enforces an authorisation tick-box on every scan and stores that attestation with your account and source IP.
Safe practice targets: your own lab VMs and containers (e.g. Metasploitable2), your home network, and
`scanme.nmap.org` (published by the Nmap project for testing, keep it light: Fast profile).

---

## Features

- Register / login with username + password (scrypt-hashed, per-user salt), session cookies, login throttling
- Targets: single IPv4, CIDR up to /24, or a public hostname
- Scan profiles: **Fast**, **Moderate**, **Deep**, each with a user-set hard time limit
- Custom ports: `22,80,443`, `1-1024`, `22,8000-8100`, or `all`
- Host, OS, open ports, service/product/version detection
- CVE correlation from NVD API 2.0 (CPE matching, CVSS score and severity, known-exploited flag), cached in Postgres
- Live progress bar with the current phase, and a cancel button
- Results dashboard: summary tiles, severity donut, top-ports chart, OS chart, per-host details
- One-click PDF report (executive summary, charts, host overview, per-host ports and CVEs)
- Fully containerised: web app + PostgreSQL, tables created automatically on first start

---

## Installation

### Prerequisites
- Docker Engine + Docker Compose v2 (`docker compose version`)
- Git
- Internet access from the container (for NVD lookups)

### Option A: Docker Compose from GitHub (recommended)

```bash
git clone https://github.com/<your-username>/netrec.git
cd netrec
cp .env.example .env
```

Fill `.env` automatically with random values:

```bash
python3 - <<'PY'
import secrets
s = open(".env.example").read()
s = s.replace("SECRET_KEY=", "SECRET_KEY=" + secrets.token_hex(32), 1)
s = s.replace("DB_PASSWORD=", "DB_PASSWORD=" + secrets.token_hex(16), 1)
open(".env", "w").write(s)
PY
```

Start it:

```bash
docker compose up -d --build
```

Open **http://localhost:8000**, register an account, run a scan.

| Command | Purpose |
|---|---|
| `docker compose logs -f web` | follow application logs |
| `docker compose ps` | check health of web and db |
| `docker compose down` | stop (keeps database) |
| `docker compose down -v` | stop and **wipe** database |

> Keep your `.env`. The database volume is created with the first `DB_PASSWORD`; changing it later makes Postgres
> reject the app (fix: `docker compose down -v` and start again, which deletes data).

### Option B: Scan other Docker containers (lab network)

Containers on different Docker networks cannot reach each other. To scan a target container such as Metasploitable2,
put both on a shared network:

```bash
docker network create netrec-lab
docker network connect netrec-lab <target-container-name>
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d --build
docker inspect -f '{{(index .NetworkSettings.Networks "netrec-lab").IPAddress}}' <target-container-name>
```

Scan the printed IP. Verify reachability first:

```bash
docker compose exec web nmap -Pn -p 21,22,80 <that-ip>
```

Do **not** scan `127.0.0.1` or Docker-published ports: loopback is blocked, and inside the container it would be NetRec itself.

### Option C: Linux host networking (full LAN discovery)

Gives ARP/MAC visibility on your real LAN. Linux only (Docker Desktop on Windows/macOS cannot do true host networking).

```bash
docker compose -f docker-compose.yml -f docker-compose.host.yml up -d --build
```

### Option D: Without Docker (development)

```bash
sudo apt install nmap python3-venv
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))")
export DATABASE_URL=sqlite:///netrec.db        # or a postgresql+psycopg2:// URL
gunicorn -b 127.0.0.1:8000 --workers 1 --threads 8 wsgi:app
```

Without raw-socket privileges NetRec falls back to TCP connect scans and **no OS detection**. For full capability run
with `sudo -E` and `export NMAP_PRIVILEGED=1`. Keep `--workers 1` (scan jobs live in the worker process).

### Configuration (`.env`)

| Variable | Required | Purpose |
|---|---|---|
| `SECRET_KEY` | yes | signs session cookies |
| `DB_PASSWORD` | yes | Postgres password (letters/digits only, it goes in a URL) |
| `NVD_API_KEY` | no | free key, ~10x faster CVE lookups: https://nvd.nist.gov/developers/request-an-api-key |
| `COOKIE_SECURE` | no | set `1` only when served over HTTPS |

Limits live in `app/config.py`: `MAX_HOSTS` 256, `MAX_TIMEOUT_MIN` 60, `MAX_CONCURRENT` 2, `CVE_BUDGET_SEC` 240.

---

## Usage

1. **Register / sign in.**
2. **Target:** IP, CIDR (`192.168.1.0/24`) or hostname.
3. **Profile and time limit:** see table below. The time limit is a hard cap; on expiry nmap is interrupted and partial results are kept and flagged.
4. **Ports:** blank = profile default, or a custom list/range.
5. Tick **Treat hosts as online** for internet targets that drop ping, otherwise nmap may report them as down.
6. Tick the **authorisation** box and start the scan. Watch progress; cancel any time.
7. Review results, expand hosts, click **PDF report** to download.

| Profile | Ports | Version probing | OS detection | Default limit |
|---|---|---|---|---|
| Fast | top 100 | light (`--version-intensity 0`) | no | 5 min |
| Moderate | top 1000 | normal (`--version-intensity 5`) | yes | 15 min |
| Deep | 1-65535 | full (`--version-all`) | yes | 45 min |

All profiles use SYN scan (`-sS`) with `-T4` when raw sockets are available.

---

## Architecture

```
 Browser (vanilla JS SPA)
   |  JSON over HTTP, session cookie, polls scan status every 1.5 s
   v
 +--------------------------- web container -----------------------------+
 |  gunicorn (1 worker, 8 threads) -> Flask app                          |
 |                                                                       |
 |  auth.py ------ register / login / logout (scrypt, throttling)        |
 |  scans.py ----- REST API + background scan thread + summary           |
 |     |  validators.py   target and port validation                     |
 |     |  scanner.py      builds nmap command, streams progress, parses  |
 |     |                  XML  --->  nmap (cap_net_raw, non-root user)   |
 |     |  cve.py          CPE -> NVD API 2.0 (rate limited, cached)  ----+--> NVD (internet)
 |     |  report.py       PDF generation (reportlab)                     |
 |  models.py ---- SQLAlchemy models                                     |
 +--------------------------------|--------------------------------------+
                                  v
                     +-------- db container --------+
                     | PostgreSQL 16                 |
                     | users | scans | cve_cache     |
                     +-------------------------------+
```

### Modules

| File | Responsibility |
|---|---|
| `app/__init__.py` | app factory; waits for Postgres, creates tables; marks scans interrupted by a restart as failed; security headers; JSON-only guard on state-changing requests |
| `app/auth.py` | registration, login, sessions, password hashing, brute-force throttling |
| `app/validators.py` | accepts only valid IPv4/CIDR/hostnames and port lists; blocks loopback, link-local, multicast, reserved; caps range size; resolves hostnames once and scans the validated IP |
| `app/scanner.py` | profiles, safe nmap argument list (no shell), progress parsing from `--stats-every`, SIGINT-based timeout/cancel, XML to structured data, CPE 2.2 to 2.3 conversion |
| `app/cve.py` | NVD API 2.0 client, global rate limiter, 7-day Postgres cache, CVSS v3.1/v3.0/v2 extraction, known-exploited flag |
| `app/scans.py` | scan lifecycle, concurrency limits, CVE correlation, summary statistics, PDF endpoint, ownership checks |
| `app/report.py` | PDF with metadata, summary, pie and bar charts, host table, per-host ports and CVEs |
| `app/static/*` | single-page UI; DOM built without `innerHTML` (scanned banners are untrusted input) |

### Data model
- `users(id, username, password_hash, created_at)`
- `scans(id, user_id, target, nmap_target, profile, ports, timeout_min, assume_up, authorized, source_ip, status, phase, progress, error, result JSON, created_at, started_at, finished_at)`
- `cve_cache(key, data JSON, fetched_at)`

### API
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/register`, `/api/login`, `/api/logout` | account session |
| GET | `/api/me` | current user |
| POST | `/api/scans` | start a scan |
| GET | `/api/scans` | your scan history |
| GET | `/api/scans/<id>` | status and, when complete, results |
| POST | `/api/scans/<id>/cancel` | stop a running scan |
| GET | `/api/scans/<id>/report.pdf` | download the PDF report |

---

## How a scan works

1. **Validate.** Target, ports, profile and time limit are checked; the authorisation attestation is required; per-user and global concurrency limits apply.
2. **Queue and run.** A row is stored and a background thread starts nmap with an argument list (no shell). A watchdog timer enforces the time limit.
3. **Progress.** nmap prints `Timing: About NN% done` every 2 s. Each phase maps to a slice of the bar: host discovery 0-8%, port scan 8-50%, service/version detection 50-82%, scripts/OS 82-85%, CVE lookup 85-99%. The bar never moves backwards.
4. **Parse.** nmap's XML becomes hosts, MAC, OS guess and accuracy, open ports, product, version and CPE.
5. **Correlate CVEs.** Each distinct service is looked up once:
   - the CPE from nmap is converted to CPE 2.3 and queried with NVD `cpeName`
   - versions like `7.6p1` are retried in NVD's split form (`7.6` + update `p1`)
   - if no CPE match, a keyword search on `product version` is used and flagged **low confidence**
   - results are sorted by CVSS and the top 25 per service are kept; everything is cached for 7 days
6. **Summarise.** Severity counts, top ports, OS mix. Low-confidence matches are shown as "possible" and excluded from headline counts.
7. **Present.** The UI renders the dashboard; the PDF is generated on demand.

---

## OpenVAS comparison

OpenVAS (the scanner inside Greenbone Vulnerability Management) runs a large feed of Network Vulnerability Tests
against targets, supports credentials, scheduling, alerts and multiple users. NetRec implements a small slice of that
workflow with a much simpler detection method.

| Capability | OpenVAS / GVM | NetRec |
|---|---|---|
| Host discovery | yes | yes (nmap) |
| Port scanning, service and OS detection | yes | yes (nmap; configurable ports, 3 profiles) |
| Vulnerability detection method | feed of thousands of active/passive tests (NVTs) | **version banner to CPE to NVD lookup only** |
| Confirms a vulnerability is really present | often (test-based, with a quality-of-detection rating) | **no** (potential exposure only) |
| Handles back-ported patches | partly (distro-aware detection) | **no** (can report false positives) |
| Authenticated (credentialed) scans | yes (SSH, SMB, SNMP...) | no |
| Web application, default-credential, misconfiguration tests | yes | no |
| Compliance / policy audits | yes | no |
| CVE data source | Greenbone feed + SCAP data | NIST NVD API 2.0 |
| Severity scoring | CVSS + quality of detection | CVSS from NVD, known-exploited flag |
| Scan time limits | yes | yes |
| Live progress | yes | yes |
| Reports | multiple formats, filters, overrides | PDF with charts |
| Users and roles | yes | basic accounts, per-user data isolation |
| Scheduling, alerts, asset management, delta reports | yes | no |
| Scale and distributed scanners | yes | single instance, 2 concurrent scans |

---

## What NetRec can do

- Find live hosts and open TCP ports in a target range you choose
- Fingerprint services, versions and (with privileges) the operating system
- Map detected versions to known CVEs with CVSS scores and flag known-exploited ones
- Run time-boxed scans, show live progress, cancel, and keep partial results
- Keep scan history per user and generate a professional PDF report
- Run anywhere Docker runs, with a one-command start

## What NetRec cannot do

- Prove a vulnerability exists or is exploitable (no active checks, no exploitation)
- Account for distribution back-ports, so patched systems can be flagged and unusual banners can be missed
- Detect vulnerabilities in services that do not reveal a version, or that nmap cannot identify
- Perform authenticated scans, web application testing, configuration or compliance audits
- Scan UDP, IPv6, or ranges larger than /24
- Match CVEs for the operating system itself (only for detected services)
- Schedule scans, send alerts, or compare scans over time
- Survive a restart mid-scan (running scans are marked failed) or scale beyond one instance
- Replace a professional assessment

Accuracy notes: results depend on nmap's banner detection and NVD's CPE data. Treat every finding as a lead to verify.
Keyword-matched findings are the least reliable and are labelled **possible**. Without an NVD API key each new service
costs about 6.5 s of lookup time; if the 4-minute budget is reached the report says so.

---

## Security design

- Passwords hashed with scrypt and per-user salt; constant-time-style dummy check prevents user enumeration; 5 failed logins per 5 minutes per IP+username
- HttpOnly, SameSite=Lax session cookies; JSON-only POSTs block cross-site form submission
- nmap invoked with an argument list; targets validated so they can never be read as options; hostnames resolved once
- Loopback, link-local (includes cloud metadata address), multicast and reserved ranges blocked
- All results rendered via DOM text nodes; strict CSP, `nosniff`, no-referrer headers
- Containers: non-root app user, nmap given only `cap_net_raw`/`cap_net_admin`, UI bound to `127.0.0.1` by default
- Do **not** expose NetRec to your LAN or the internet: it is a scanning tool with simple auth

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `required variable DB_PASSWORD is missing` | no `.env` in this folder; create it (see Option A). Compose needs it even for `down` |
| App cannot connect to database after editing `.env` | volume has the old password; restore it, or `docker compose down -v` (deletes data) |
| Host shows 0 open ports, OS unknown | target unreachable or firewalled; often a different Docker network (see Option B). Zero findings does not mean clean |
| Host reported down | tick **Treat hosts as online** |
| OS always unknown | raw sockets unavailable, or no open+closed port pair to fingerprint; use Moderate/Deep |
| CVE phase slow | add `NVD_API_KEY` |
| Scan "failed: nmap ..." | the message holds the last nmap output lines; check the target and ports |

---

## Project layout

```
netrec/
├── docker-compose.yml         web + postgres, UI on localhost:8000
├── docker-compose.lab.yml     join an external lab network (scan other containers)
├── docker-compose.host.yml    Linux host-network override
├── Dockerfile                 python + nmap (file capabilities), non-root
├── .env.example  requirements.txt  wsgi.py  README.md
└── app/
    ├── __init__.py  config.py  models.py  auth.py
    ├── validators.py  scanner.py  cve.py  scans.py  report.py
    └── static/  index.html  style.css  app.js
```

## Roadmap

- Job queue (RQ/Celery) so scans survive restarts and scale out
- NSE `vulners` / `vuln` script mode to compare banner matching with active checks
- Scan comparison (delta) and scheduling
- Tests and CI, HTTPS reverse proxy profile, IPv6 and UDP support
