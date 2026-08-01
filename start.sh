#!/usr/bin/env bash
# ==============================================================
# Mobile Security Scanner — Start API + Frontend
# Stops everything on Ctrl+C. Single command to run the full stack.
# ==============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; NC='\033[0m'
info() { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; }

cleanup() {
  echo ""
  info "Shutting down..."
  kill $API_PID 2>/dev/null || true
  kill $FRONTEND_PID 2>/dev/null || true
  wait $API_PID 2>/dev/null || true
  wait $FRONTEND_PID 2>/dev/null || true
  ok "All processes stopped"
  exit 0
}
trap cleanup SIGINT SIGTERM

ROOT="$(cd "$(dirname "$0")" && pwd)"

# ── Pick Python: prefer project venv (has reportlab/jinja2 for PDFs) ──
PY=python3
if [ -x "$ROOT/.venv/bin/python" ]; then
  PY="$ROOT/.venv/bin/python"
  if ! "$PY" -c "import reportlab, jinja2" >/dev/null 2>&1; then
    info "Installing PDF dependencies (reportlab, jinja2) into .venv..."
    "$PY" -m pip install --only-binary=:all: reportlab jinja2 >/dev/null 2>&1 || warn "PDF deps missing — PDF downloads may be unavailable"
  fi
fi
command -v python3 >/dev/null 2>&1 || { err "python3 not found"; exit 1; }

# ── Kill existing processes on required ports ──────────────
freed=false
if command -v fuser >/dev/null 2>&1; then
  for port in 5000 3000; do
    if fuser -k $port/tcp 2>/dev/null; then info "Freed port $port"; freed=true; fi
  done
elif command -v lsof >/dev/null 2>&1; then
  for port in 5000 3000; do
    pid=$(lsof -ti :$port 2>/dev/null)
    if [ -n "$pid" ]; then kill $pid 2>/dev/null && info "Freed port $port (killed PID $pid)"; freed=true; fi
  done
else
  pkill -f "backend/api/server.py" 2>/dev/null || true
  pkill -f "next dev" 2>/dev/null || true
fi
[ "$freed" = true ] && sleep 1

# ── Seed DB if empty ────────────────────────────────────────
if [ ! -f "$ROOT/backend/output/mobile_security.db" ]; then
  if [ -f "$ROOT/backend/database/seed_from_outputs.py" ]; then
    info "Seeding database from last scan outputs..."
    "$PY" "$ROOT/backend/database/seed_from_outputs.py" 2>&1 | tail -2 || warn "Seed skipped"
  fi
fi

# ── Start API server ────────────────────────────────────────
info "Starting API server on :5000..."
"$PY" "$ROOT/backend/api/server.py" &
API_PID=$!
sleep 2
if kill -0 $API_PID 2>/dev/null; then
  ok "API server running (PID $API_PID) → http://localhost:5000/api/health"
else
  err "API server failed to start"
  exit 1
fi

# ── Start frontend ──────────────────────────────────────────
if [ -d "$ROOT/frontend/nextjs" ]; then
  info "Starting Next.js frontend on :3000..."
  cd "$ROOT/frontend/nextjs"
  npm run dev &
  FRONTEND_PID=$!
  cd "$ROOT"
  sleep 4
  if kill -0 $FRONTEND_PID 2>/dev/null; then
    ok "Frontend running (PID $FRONTEND_PID) → http://localhost:3000"
  else
    warn "Frontend may have failed — check above for errors"
  fi
else
  warn "frontend/nextjs not found — skipping frontend"
  FRONTEND_PID=""
fi

echo ""
echo -e "${GREEN}════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Both services running${NC}"
echo -e "${GREEN}  Dashboard:  http://localhost:3000${NC}"
echo -e "${GREEN}  API:        http://localhost:5000${NC}"
echo -e "${GREEN}  Press Ctrl+C to stop everything${NC}"
echo -e "${GREEN}════════════════════════════════════════════════${NC}"

# Wait for either process to exit
wait
