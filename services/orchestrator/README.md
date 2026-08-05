# orchestrator (placeholder — not implemented)

This service directory looks like scaffolding for a "containerize the
orchestrator itself" idea. The real orchestrator that drives the scan
pipeline is `backend/orchestrator/orchestrator.py`, which runs on the host
and calls `docker compose run` per stage — that is the actual, working
implementation.

This directory is **not** referenced anywhere in `compose.yaml`, its
`Dockerfile`/`requirements.txt` are empty, and it does not build or run.

Left in place intentionally rather than deleted, since the scaffolding may be
a starting point for future work — if you're picking this up, treat it as an
empty shell, not an in-progress feature.
