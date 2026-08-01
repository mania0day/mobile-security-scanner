"""
Orchestrator configuration — reads paths from environment with defaults.
"""
import os
from pathlib import Path

# Absolute path to the project root (parent of backend/)
# When running on the host, this is wherever the project is checked out.
PROJECT_ROOT = os.environ.get(
    "PROJECT_ROOT",
    str(Path(__file__).resolve().parents[2]),  # backend/orchestrator/../../
)

# Path to the Docker Compose file
COMPOSE_FILE = os.environ.get(
    "COMPOSE_FILE",
    str(Path(PROJECT_ROOT) / "compose.yaml"),
)

# Output base directory (on host filesystem)
OUTPUT_BASE = os.environ.get(
    "OUTPUT_BASE",
    str(Path(PROJECT_ROOT) / "backend" / "output"),
)
