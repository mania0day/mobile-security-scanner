# Mobile Security Scanner

A workstation-based BYOD admission scanner for Android and iOS. Plug a
phone into USB, run an 8-category compliance audit across a pipeline of
isolated Docker microservices, and get back a PASS / CONDITIONAL / FAIL
verdict plus a downloadable PDF admission certificate — backed by a
Next.js dashboard and a scan history database.

```
   USB phone  ──▶  orchestrator.py  ──▶  per-service Docker containers  ──▶  risk_engine  ──▶  reports + SQLite  ──▶  Next.js dashboard
```

---

## Table of contents

- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Service catalog](#service-catalog)
- [Scan modes](#scan-modes)
- [Risk scoring & verdict logic](#risk-scoring--verdict-logic)
- [Tech stack](#tech-stack)
- [Project structure](#project-structure)
- [Getting started](#getting-started)
- [Environment variables](#environment-variables)
- [Web API reference](#web-api-reference)
- [Database schema](#database-schema)
- [Output files](#output-files)

---

## What it does

1. Detects a connected Android (ADB) or iOS (usbmux) device automatically.
2. Pulls device identity, installed-app inventory, and APKs (Android) or
   plist/binary/provisioning data (iOS).
3. Runs a battery of security analysis microservices **in parallel Docker
   containers**, each one purpose-built and independently testable.
4. Aggregates every finding into an 8-category BYOD admission checklist
   with a Must / Should / Nice-to-have priority scheme.
5. Computes a 0–100 risk score and a PASS / CONDITIONAL / FAIL verdict.
6. Generates JSON, HTML, TXT, and PDF reports (full, IMEI-redacted "safe",
   and a one-page executive summary).
7. Persists every scan to SQLite so the dashboard can show device history,
   trends, and let you re-download any past report.

## Architecture

Every analysis step is a **stateless, one-shot Docker container**: it reads
JSON from `backend/output/<previous-service>/`, does one job, writes JSON to
`backend/output/<its-own-service>/`, and exits. Containers never talk to each
other directly — the host-side orchestrator (`backend/orchestrator/`) is the
only thing that sequences them, using `docker compose run --rm` so nothing is
left behind between scans.

```
                       ┌─────────────────────────────────────────┐
                       │   orchestrator.py (host, Python)         │
                       │   • picks the pipeline for platform+mode │
                       │   • wipes stale per-service outputs      │
                       │   • runs independent stages in parallel  │
                       │   • runs dependent stages in sequence    │
                       └───────────────┬───────────────────────────┘
                                        │  docker compose run --rm <service>
                                        ▼
   ┌─────────┐   ┌──────────────┐   ┌────────────────────────────┐
   │  adb /  │──▶│  inventory + │──▶│  analysis containers        │
   │ios_device│   │  extraction  │   │  (apkid, androguard, cert,  │
   └─────────┘   └──────────────┘   │  permission_analyzer, yara, │
                                     │  root/jailbreak detection,  │
                                     │  cve_checker, hash_lookup)  │
                                     └───────────────┬─────────────┘
                                                      ▼
                                        ┌───────────────────────┐
                                        │      risk_engine       │
                                        │  8-category checklist  │
                                        │  Must/Should/Nice eval  │
                                        │  0–100 score + verdict │
                                        └───────────┬─────────────┘
                                                    ▼
                                        ┌───────────────────────┐
                                        │   report_generator     │
                                        │  JSON/HTML/TXT/PDF      │
                                        │  writes to SQLite too  │
                                        └───────────┬─────────────┘
                                                    ▼
                              backend/api/server.py  ⇄  Next.js dashboard
```

Every container is built `FROM mobile-base:latest` — a shared base image
with the Python/system dependencies every service needs, so per-service
images only add their own tool and rebuild fast on top of a cached base
layer. Pure analysis services (androguard, apkid, certificate, cve_checker,
hash_lookup, permission_analyzer, yara, risk_engine, report_generator, and
their iOS equivalents) run as a **non-root `appuser`** (uid 1000, matching
the host user) so bind-mounted output files stay host-writable. Services
that talk directly to the device over ADB/usbmux (`adb`, `apk_inventory`,
`apk_extractor`, `ios_device`, `root_detection`, `jailbreak_detection`,
`mvt`) still run as root inside their container.

## Service catalog

### Android pipeline

| Service | Role |
|---|---|
| `adb` | Detects the device over ADB, pulls model/serial/IMEI/SIM, screen-lock and encryption state |
| `apk_inventory` | Lists every installed package (`pm list packages`) |
| `apk_extractor` | Pulls the APK file for each package off the device |
| `apkid` | Detects packers, obfuscators, and anti-debug/anti-VM tricks in each APK |
| `androguard` | Parses manifests — permissions, exported components, SDK levels |
| `certificate` | Validates the APK signing certificate (expired, weak algorithm, debug-signed) |
| `permission_analyzer` | Classifies each declared permission by risk tier (critical/high/medium) |
| `root_detection` | Checks for Magisk/SuperSU artifacts, writable `/data/adb` overlay mounts, test-keys, unlocked bootloader |
| `cve_checker` | Matches the device's Android version + security patch date against known unpatched CVEs |
| `hash_lookup` | SHA-256 hashes every APK; optional VirusTotal lookup (Deep mode, opt-in) |
| `yara` | Scans each APK against local YARA rules for malware-pattern strings |

### iOS pipeline

| Service | Role |
|---|---|
| `ios_device` | Detects the iPhone/iPad over usbmux, pulls model/iOS version/UDID |
| `plist_analyzer` | Parses `Info.plist` — permissions, entitlements, exported capabilities |
| `macho_analyzer` | Checks Mach-O binary hardening (PIE, ARC, stack canaries) |
| `ios_certificate` | Validates provisioning profiles and developer signing certificates |
| `jailbreak_detection` | Checks for Cydia, `.installed_unc0ver`, resigned system apps, and other jailbreak artifacts |

### Shared (both platforms)

| Service | Role |
|---|---|
| `mobsf` | Full static analysis via a local MobSF REST server (Deep mode) |
| `mvt` | Mobile Verification Toolkit spyware IOC scan — Pegasus-class indicators (Deep mode) |
| `risk_engine` | Aggregates every upstream service's findings into the 8-category checklist, computes the 0–100 score and PASS/CONDITIONAL/FAIL verdict, writes the scan to SQLite |
| `report_generator` | Renders JSON/HTML/TXT/PDF reports (full, IMEI-redacted, and one-pager) from the risk_engine output |

The 8 checklist categories evaluated by `risk_engine` are: **identity**,
**root/jailbreak**, **lock & encryption**, **installed apps**, **network**,
**certificates**, **management (MDM readiness)**, and **backup**.

## Scan modes

| | Quick | Minimal | Deep |
|---|---|---|---|
| Runtime | ~5–10s | ~5–15 min | ~20–40 min |
| Device identity, root/jailbreak, lock & encryption | ✅ | ✅ | ✅ |
| Full app inventory + APK extraction | ❌ | ✅ | ✅ |
| Permission analysis, APKID, certificate checks | ❌ | ✅ | ✅ |
| YARA malware scan | ❌ | ✅ | ✅ |
| CVE check vs. security patch level | ❌ | ✅ | ✅ |
| VirusTotal hash lookup | ❌ | ❌ | ✅ (opt-in, needs `VT_API_KEY`) |
| MobSF full static analysis | ❌ | ❌ | ✅ (needs `MOBSF_API_KEY`) |
| MVT spyware IOC scan | ❌ | ❌ | ✅ (`MVT_ENABLED=true`) |

Quick mode runs a single bundled ADB/usbmux probe and skips every
app-inventory service entirely — this is intentional (not a bug): app-level
checks genuinely were not collected, so `risk_engine` reports them as an
honest `WARNING` ("not evaluated in Quick mode") rather than a false `PASS`.
That's why a clean device on Quick mode still lands on `CONDITIONAL` instead
of `PASS` — it's flagging incomplete coverage, not a failure. Run Minimal or
Deep for the full picture.

## Risk scoring & verdict logic

`risk_engine` (`services/risk_engine/src/`) does two independent things:

**1. The pass/fail checklist** (`evaluator.py`) — every check has a priority:
- **Must** — blocking. Any Must-priority `FAIL` → verdict `FAIL` (reject admission).
- **Should** — a `FAIL` or `WARNING` at this level → verdict `CONDITIONAL`.
- **Nice to have** — informational only, never blocks.

**2. The numeric score** (`service.py` + `weights.py`) — device-level
findings (rooted, unlocked bootloader, permissive SELinux, debuggable build)
and per-app findings (YARA hits, weak/expired certs, dangerous permissions,
packer/obfuscation flags) each accumulate weighted points, capped at 100 per
app. `overall_score` is the device score vs. the **average** app score,
whichever is higher — deliberately *not* the single worst-scoring app, since
one legitimately permission-heavy system app (e.g. Google Play Services)
would otherwise dominate the whole device's score.

The permission-combination check specifically looks for Accessibility-service
binding paired with Device Admin, Overlay, or SMS permissions on the *same*
app — the actual pattern used by real Android banking trojans/spyware
(screen-read + auto-click + draw-over-UI) — rather than flagging any single
common permission, which would false-positive on nearly every stock
OEM/AOSP component.

## Tech stack

**Backend / pipeline**
- Python 3.12, one Flask-free stdlib HTTP API (`backend/api/server.py`)
- Docker + Docker Compose — every analysis step is an isolated container
- SQLite for scan history (`backend/output/mobile_security.db`)
- ADB (Android) / usbmux (iOS) for device communication
- YARA, Androguard, APKiD, MobSF, MVT for static/dynamic analysis
- ReportLab for PDF generation

**Frontend** (`frontend/nextjs/`)
- Next.js 14 (App Router) + TypeScript
- Tailwind CSS with a custom design system (`tailwind.config.js`)
- Framer Motion for page transitions, staggered lists, the animated risk
  gauge, and spring-based micro-interactions
- Recharts for the risk-distribution, category-health, and top-risk-app charts
- lucide-react icons

## Project structure

```
mobile-security-scanner/
├── backend/
│   ├── api/                 ← Stdlib HTTP API (scans, devices, PDFs, live scan control)
│   ├── database/            ← SQLite schema + query helpers
│   ├── orchestrator/        ← Host-side pipeline controller (orchestrator.py, pipeline.py, runner.py)
│   └── output/               ← Every service's JSON output + generated reports (git-ignored)
├── services/
│   ├── shared/               ← Shared Python utilities (logging, JSON I/O)
│   ├── adb/ · apk_inventory/ · apk_extractor/ · apkid/ · androguard/
│   ├── certificate/ · permission_analyzer/ · root_detection/ · cve_checker/ · hash_lookup/ · yara/
│   ├── ios_device/ · plist_analyzer/ · macho_analyzer/ · ios_certificate/ · jailbreak_detection/
│   ├── mobsf/ · mvt/         ← Deep-mode only
│   ├── risk_engine/          ← Checklist evaluator + scoring (evaluator.py, service.py, weights.py)
│   └── report_generator/     ← JSON/HTML/TXT/PDF report rendering
├── docker/
│   └── base-python/          ← Shared base image (non-root `appuser`, common deps)
├── frontend/
│   └── nextjs/                ← Dashboard (src/app, src/components, src/lib)
├── compose.yaml                ← One service definition per container
└── start.sh                    ← Single command: API + dashboard, kills stale ports, seeds DB if empty
```

## Getting started

### Requirements
- Linux with Docker + Docker Compose
- Python 3.12
- Node.js 18+ (for the dashboard)
- Android phone with USB debugging enabled, and/or an iPhone with usbmux (`libimobiledevice`)

### 1. Connect a device
Android: enable **Developer Options → USB Debugging**, plug in, accept the
trust prompt. iOS: plug in, trust the computer.

### 2. Build the base image (once, and again after changing shared deps)
```bash
docker build -t mobile-base:latest ./docker/base-python/
```

### 3. Run the full stack
```bash
./start.sh
```
This frees ports 5000/3000 if something stale is holding them, seeds the
database from the last scan output if empty, and starts the API (`:5000`)
and the Next.js dashboard (`:3000`). Press Ctrl+C to stop both.

Open **http://localhost:3000**, pick a connected device, choose Quick /
Minimal / Deep, and start the scan from the dashboard.

### Or run a scan directly from the CLI
```bash
python3 backend/orchestrator/orchestrator.py --mode minimal --platform auto
```
`--mode` is `quick` / `minimal` / `deep`; `--platform` is `auto` / `android` /
`ios` (auto-detects by default). Deep mode needs `mobsf-server` running
first if `MOBSF_ENABLED=true`:
```bash
docker compose up -d mobsf-server
```

### Output
- PDF/HTML/JSON/TXT reports → `backend/output/reports/`
- Scan history → `backend/output/mobile_security.db`
- Raw per-service data → `backend/output/<service>/`

## Environment variables

Create a `.env` in the project root:

```env
LOG_LEVEL=INFO

# Deep-mode only — all optional/opt-in
VT_API_KEY=              # VirusTotal API key (hash_lookup)
MOBSF_API_KEY=            # MobSF API key (set after first mobsf-server run)
MOBSF_ENABLED=false
MVT_ENABLED=false

ADB_TIMEOUT=30
INCLUDE_SYSTEM_APPS=true
EXTRACT_SYSTEM_APPS=false
```

## Web API reference

Base URL: `http://localhost:5000`

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | API liveness check |
| GET | `/api/connected` | USB-connected devices ready to scan |
| GET | `/api/stats` | Aggregate dashboard stats |
| GET | `/api/scans` | All scans (newest first), joined with device info |
| GET | `/api/scans/:id` | Full scan detail — checklist, app findings, CVE data |
| DELETE | `/api/scans/:id` | Delete a scan and its checklist/app-finding rows |
| GET | `/api/devices` | All devices with scan history |
| GET | `/api/devices/:id` | Single device detail + its scans |
| DELETE | `/api/devices/:id` | Delete a device and all its scans |
| GET | `/api/reports/pdf?scan_id=...` | Download a PDF (`?safe=1` for IMEI-redacted, `?onepager=1` for the executive summary) |
| POST | `/api/scan/start` | Launch a live scan (`mode`, `platform`, `serial`, `vt_enabled`) |
| POST | `/api/scan/cancel` | Cancel the running scan |
| GET | `/api/scan/status` | Poll live-scan progress |
| GET | `/api/scan/logs` | Tail the running scan's orchestrator log |

## Database schema

`backend/output/mobile_security.db` (SQLite):

- **`devices`** — one row per physical device (keyed by serial), identity + last-seen scan metadata
- **`scan_sessions`** — one row per scan run: mode, verdict, overall score, app/critical counts, CVE findings JSON
- **`checklist_evaluations`** — one row per 8-category checklist item per scan (category, priority, status, details)
- **`app_findings`** — one row per analyzed app per scan (risk score/level, risk factors, YARA matches, permissions, cert issues)

## Output files

Each scan writes to `backend/output/reports/`:
- `report.json` / `report.html` / `report.txt` — full machine/human-readable reports
- `report.pdf` — full PDF certificate (includes IMEI/phone/SIM)
- PDF variants are also available IMEI-redacted (`safe`) and as a one-page executive summary (`onepager`) via the API/dashboard

Every upstream service's raw findings live at `backend/output/<service>/` for
debugging or re-processing without re-scanning the device.

## License

MIT
