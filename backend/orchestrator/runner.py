"""
ServiceRunner — executes individual Docker Compose services.

Why docker compose run instead of docker compose up?
`docker compose up` is for long-running services (servers).
`docker compose run` is for one-shot tasks — it runs the container,
waits for it to finish, then exits. Perfect for our pipeline pattern.

Each scanner service:
  1. Runs as a one-shot container
  2. Reads input from backend/output/ (shared volume)
  3. Writes output to backend/output/<service>/ (shared volume)
  4. Exits with code 0 (success) or non-zero (failure)
"""
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger("ServiceRunner")


class ServiceRunner:
    """
    Wraps docker compose run to execute pipeline services.

    Args:
        project_root: Absolute path to the project root directory.
        compose_file:  Path to the docker-compose file.
    """

    def __init__(self, project_root: str, compose_file: str, env: dict | None = None):
        self.project_root = Path(project_root)
        self.compose_file = compose_file
        self.extra_env = dict(env or {})

    def run_service(self, service_name: str, timeout: int = 600) -> bool:
        """
        Run a single service via docker compose run.

        Args:
            service_name: Name of the service in compose.yaml
            timeout:      Max seconds to wait (default 10 minutes)

        Returns:
            True if the service completed successfully (exit 0), False otherwise.
        """
        command = [
            "docker", "compose",
            "-f", self.compose_file,
            "run",
            "--build",       # Rebuild from source if any service files changed (cached otherwise)
            "--rm",          # Remove container after it exits
            "--no-deps",     # Don't start linked services (orchestrator manages order)
        ]
        for key, value in self.extra_env.items():
            command.extend(["-e", f"{key}={value}"])
        command.append(service_name)

        logger.debug(f"  Running: {' '.join(command)}")

        try:
            result = subprocess.run(
                command,
                cwd=str(self.project_root),
                timeout=timeout,
                capture_output=False,  # Let output stream to terminal
                check=False,
            )
            return result.returncode == 0

        except subprocess.TimeoutExpired:
            logger.error(
                f"  Service '{service_name}' timed out after {timeout}s"
            )
            return False

        except FileNotFoundError:
            logger.error(
                "  'docker' command not found. "
                "Is Docker installed and on PATH?"
            )
            return False

        except Exception as exc:
            logger.error(f"  Unexpected error running {service_name}: {exc}")
            return False

    def build_base_image(self) -> bool:
        """
        Build the base Docker image that all Python services inherit from.
        Must be called before running any service.
        """
        logger.info("Building base Docker image (mobile-base:latest)...")

        command = [
            "docker", "build",
            "-t", "mobile-base:latest",
            str(self.project_root / "docker" / "base-python"),
        ]

        result = subprocess.run(
            command,
            cwd=str(self.project_root),
            timeout=300,
            capture_output=False,
            check=False,
        )

        if result.returncode == 0:
            logger.info("Base image built successfully")
            return True
        else:
            logger.error("Failed to build base image")
            return False
