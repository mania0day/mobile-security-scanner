# Mobile Security Scanner

A workstation-based Android forensic security assessment platform.
Analyzes a connected Android device using multiple security tools,
each running in its own Docker container.

## What it does

1. Connects to an Android phone via USB (ADB)
2. Inventories all installed apps
3. Extracts APK files
4. Runs multiple security analysis tools in parallel
5. Correlates all findings
6. Calculates a risk score
7. Generates a report (JSON + HTML)

## Requirements

- Fedora (or any Linux with Docker)
- Docker + Docker Compose
- Python 3.12 (for the orchestrator)
- Android phone with USB debugging enabled

## Quick Start

### 1. Connect your Android phone
Enable **Developer Options** → **USB Debugging** on the phone.
Connect via USB. Trust the computer when prompted.

### 2. Clone and configure
```bash
git clone <repo>
cd mobile-security-scanner
cp .env.example .env   # edit with your API keys if doing a deep scan
```

### 3. Build the base Docker image
```bash
docker build -t mobile-base:latest ./docker/base-python/
```

### 4. Run a scan

**Minimal scan** (offline, no API keys needed):
```bash
python backend/orchestrator/orchestrator.py --mode minimal
```

**Deep scan** (requires API keys in .env):
```bash
# First start MobSF server
docker compose up -d mobsf-server

# Then run deep scan
python backend/orchestrator/orchestrator.py --mode deep
```

### 5. View results
- **HTML report**: `backend/output/reports/report.html`
- **JSON report**: `backend/output/reports/report.json`
- **PDF certificate**: `backend/output/reports/report.pdf`
- **SQLite history**: `backend/output/mobile_security.db`
- **Raw data**: `backend/output/<service>/`

### 6. Web dashboard (device history + PDF download)
```bash
# Terminal A — REST API (reads SQLite + serves PDFs)
python backend/api/server.py

# Optional: re-seed DB from last scan outputs
python backend/database/seed_from_outputs.py

# Terminal B — Next.js UI
cd frontend/nextjs && npm install && npm run dev
# → http://localhost:3000
```

## Project Structure

```
mobile-security-scanner/
├── backend/
│   ├── orchestrator/       ← Host-side pipeline controller
│   └── output/             ← All service JSON outputs + reports
├── services/
│   ├── shared/             ← Shared Python utilities
│   ├── adb/                ← Device detection
│   ├── apk_inventory/      ← List installed apps
│   ├── apk_extractor/      ← Pull APK files from device
│   ├── apkid/              ← Packer/obfuscation detection
│   ├── androguard/         ← Manifest analysis
│   ├── certificate/        ← Signing certificate analysis
│   ├── permission_analyzer/← Permission risk classification
│   ├── root_detection/     ← Root/tamper detection
│   ├── hash_lookup/        ← SHA256 + VirusTotal lookup
│   ├── yara/               ← Malware signature scanning
│   ├── mobsf/              ← Full static analysis (deep scan)
│   ├── mvt/                ← Spyware IOC detection (deep scan)
│   ├── risk_engine/        ← Score aggregation
│   └── report_generator/   ← HTML + JSON reports
├── docker/
│   └── base-python/        ← Base Docker image for Python services
├── frontend/
│   └── nextjs/             ← Web dashboard (optional)
└── compose.yaml            ← Docker Compose definitions
```

## Scan Modes

| Feature | Minimal | Deep |
|---|---|---|
| Device detection | ✅ | ✅ |
| APK extraction | ✅ | ✅ |
| APKID (packer detection) | ✅ | ✅ |
| Androguard (manifest) | ✅ | ✅ |
| Certificate analysis | ✅ | ✅ |
| Permission analysis | ✅ | ✅ |
| Root detection | ✅ | ✅ |
| YARA (local rules) | ✅ | ✅ |
| Hash generation | ✅ | ✅ |
| VirusTotal lookup | ❌ | ✅ (requires VT_API_KEY) |
| MobSF full analysis | ❌ | ✅ (requires MOBSF_API_KEY) |
| MVT spyware check | ❌ | ✅ (requires MVT_ENABLED=true) |

## Environment Variables (.env)

```env
LOG_LEVEL=INFO

# API Keys (required for deep scan only)
VT_API_KEY=           # VirusTotal API key
MOBSF_API_KEY=        # MobSF API key (set after first run)
MOBSF_ENABLED=false   # Set to true for deep scan

# ADB
ADB_TIMEOUT=30

# Scan options
INCLUDE_SYSTEM_APPS=true
EXTRACT_SYSTEM_APPS=false
```

## Architecture

Every service is a Docker container that:
- Reads its input from `backend/output/` (previous stage)
- Writes its output to `backend/output/<service>/`
- Exits when done

The orchestrator (Python script on the host) runs them in order.
No service talks to another service directly — only via JSON files.

## License

MIT
