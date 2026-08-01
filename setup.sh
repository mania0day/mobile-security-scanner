#!/usr/bin/env bash
# ==============================================================
# Mobile Security Scanner — Cross-platform setup script
# Supports: Linux, macOS, Windows (WSL2 / Git Bash)
# ==============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }

detect_os() {
  case "$(uname -s)" in
    Linux*)   echo "linux" ;;
    Darwin*)  echo "macos" ;;
    CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
    *)        echo "unknown" ;;
  esac
}

check_cmd() {
  if ! command -v "$1" &>/dev/null; then
    err "$1 is required but not found."
    case "$(detect_os)" in
      linux)  echo "  Install: sudo apt install $1  (or sudo dnf install $1)" ;;
      macos)  echo "  Install: brew install $1" ;;
      windows) echo "  Install via: winget install $1  (or in WSL: sudo apt install $1)" ;;
    esac
    return 1
  fi
  ok "$1 found: $(command -v "$1")"
}

OS=$(detect_os)
echo -e "${CYAN}════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Mobile Security Scanner — Setup${NC}"
echo -e "${CYAN}  OS: ${OS}${NC}"
echo -e "${CYAN}════════════════════════════════════════════════${NC}"
echo ""

# ── Prerequisites ──────────────────────────────────────────
info "Checking prerequisites..."
PREREQ_OK=true

check_cmd "docker"    || PREREQ_OK=false
check_cmd "python3"   || PREREQ_OK=false
check_cmd "pip3"      || PREREQ_OK=false
check_cmd "node"      || PREREQ_OK=false
check_cmd "npm"       || PREREQ_OK=false

if [ "$OS" = "linux" ]; then
  if command -v adb &>/dev/null; then
    ok "adb found: $(command -v adb)"
  else
    warn "adb not found. Install Android SDK platform-tools or run:"
    echo "    sudo apt install adb  (or sudo dnf install android-tools)"
  fi
fi

if [ "$OS" = "windows" ]; then
  check_cmd "git"     || PREREQ_OK=false
fi

echo ""

# ── Docker check ────────────────────────────────────────────
if ! docker info &>/dev/null; then
  warn "Docker daemon is not running. Start it and retry."
  case "$OS" in
    linux)   echo "  sudo systemctl start docker" ;;
    macos)   echo "  Open Docker Desktop app" ;;
    windows) echo "  Open Docker Desktop or: sudo service docker start" ;;
  esac
  PREREQ_OK=false
fi

if [ "$PREREQ_OK" = false ]; then
  echo ""
  err "Fix the missing prerequisites above, then re-run this script."
  exit 1
fi

# ── Python dependencies ────────────────────────────────────
info "Installing Python dependencies..."
pip3 install --quiet --user reportlab 2>&1 | tail -1 || warn "reportlab install had warnings"
ok "Python dependencies ready"

# ── Base Docker image ──────────────────────────────────────
info "Building base Docker image (mobile-base:latest)..."
if [ -f "docker/base-python/Dockerfile" ]; then
  docker build -t mobile-base:latest ./docker/base-python/ 2>&1 | tail -3
  ok "Docker base image built"
else
  warn "docker/base-python/Dockerfile not found — skipping image build"
fi

# ── Node modules ────────────────────────────────────────────
info "Installing frontend dependencies..."
if [ -d "frontend/nextjs" ]; then
  cd frontend/nextjs
  npm install --silent 2>&1 | tail -3
  cd ../..
  ok "Frontend dependencies installed"
else
  warn "frontend/nextjs directory not found — skipping"
fi

# ── .env ────────────────────────────────────────────────────
if [ ! -f ".env" ]; then
  if [ -f ".env.example" ]; then
    cp .env.example .env
    ok "Created .env from .env.example — edit API keys for deep scan"
  else
    warn "No .env or .env.example found — create one manually"
  fi
else
  ok ".env exists"
fi

# ── Output dir ──────────────────────────────────────────────
mkdir -p backend/output/reports backend/output/risk_engine
ok "Output directories ready"

# ── Summary ─────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Setup complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Start everything:${NC}  bash start.sh"
echo ""
echo -e "  ${CYAN}Or manually:${NC}"
echo "    Terminal A — API server:"
echo "      python3 backend/api/server.py"
echo ""
echo "    Terminal B — Frontend:"
echo "      cd frontend/nextjs && npm run dev"
echo ""
echo -e "  ${CYAN}Run a scan (no UI):${NC}"
echo "      python3 backend/orchestrator/orchestrator.py --mode minimal"
echo ""
echo -e "  ${CYAN}Re-seed DB from last scan:${NC}"
echo "      python3 backend/database/seed_from_outputs.py"
echo ""
echo -e "  ${CYAN}Dashboard:${NC}  http://localhost:3000"
echo -e "  ${CYAN}API:${NC}       http://localhost:5000/api/health"
echo ""
