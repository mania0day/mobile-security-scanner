import time
import requests
from pathlib import Path

from shared.json_writer import read_json, write_json
from shared.logger import get_logger

from config import (
    MOBSF_URL, MOBSF_API_KEY, MOBSF_ENABLED,
    INVENTORY_OUTPUT_DIR, OUTPUT_DIR,
    UPLOAD_TIMEOUT, SCAN_TIMEOUT, REPORT_TIMEOUT,
)
from exceptions import MobSFConnectionError, MobSFUploadError, MobSFScanError
from models import MobSFResult


class MobSFService:
    """
    Uploads APKs to a running MobSF server and retrieves security reports.

    DEEP SCAN ONLY — skips gracefully if MOBSF_ENABLED is not set.

    Why a persistent server?
    MobSF runs Django + Java. Cold startup takes 30-60 seconds.
    We keep it running as a Docker service (`depends_on: mobsf`)
    and just call its REST API from this container.

    MobSF REST API flow:
      1. POST /api/v1/upload       → upload APK, get file_hash
      2. POST /api/v1/scan         → trigger analysis, get scan_type
      3. POST /api/v1/report_json  → fetch the full report JSON

    Reads:  backend/output/apk_inventory/extracted.json
    Writes: backend/output/mobsf/results.json
    """

    def __init__(self):
        self.logger = get_logger("MobSF")
        self._headers = {"Authorization": MOBSF_API_KEY}

    def run(self) -> None:
        self.logger.info("Starting MobSF service")

        if not MOBSF_ENABLED:
            self.logger.info(
                "MOBSF_ENABLED not set — skipping (deep scan only)"
            )
            self._write_skipped_result()
            return

        if not MOBSF_API_KEY:
            self.logger.warning("MOBSF_API_KEY not set — cannot authenticate")
            self._write_skipped_result("MOBSF_API_KEY not configured")
            return

        self._wait_for_mobsf()

        extracted = read_json(f"{INVENTORY_OUTPUT_DIR}/extracted.json")
        apk_entries = [
            e for e in extracted.get("results", [])
            if e.get("status") == "success"
        ]

        self.logger.info(f"Analysing {len(apk_entries)} APKs via MobSF")

        results = []
        for entry in apk_entries:
            result = self._analyse_apk(entry)
            results.append(result)

        self._save(results)
        self.logger.info("MobSF service finished")

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _wait_for_mobsf(self, retries: int = 10, delay: int = 10) -> None:
        """Poll MobSF until it's ready to accept requests."""
        self.logger.info(f"Waiting for MobSF at {MOBSF_URL}...")
        for attempt in range(retries):
            try:
                r = requests.get(f"{MOBSF_URL}/api/v1/ping",
                                 headers=self._headers, timeout=5)
                if r.status_code == 200:
                    self.logger.info("MobSF is ready")
                    return
            except requests.exceptions.ConnectionError:
                pass
            self.logger.info(
                f"  MobSF not ready (attempt {attempt + 1}/{retries}), "
                f"waiting {delay}s..."
            )
            time.sleep(delay)

        raise MobSFConnectionError(
            f"MobSF did not become ready after {retries * delay}s. "
            f"Is the mobsf Docker service running?"
        )

    def _analyse_apk(self, entry: dict) -> dict:
        """Upload, scan, and fetch report for one APK."""
        package_name = entry.get("package_name", "unknown")
        apk_path = entry.get("local_path", "")

        result = MobSFResult(
            package_name=package_name,
            apk_path=apk_path,
        )

        try:
            self.logger.info(f"  Uploading {package_name}...")
            file_hash = self._upload(apk_path)
            result.hash = file_hash
            result.file_name = Path(apk_path).name

            self.logger.info(f"  Scanning {package_name} (hash={file_hash})...")
            self._trigger_scan(file_hash, result.file_name)

            self.logger.info(f"  Fetching report for {package_name}...")
            report = self._fetch_report(file_hash)

            self._parse_report(result, report)

        except Exception as exc:
            self.logger.error(f"  MobSF failed for {package_name}: {exc}")
            result.error = str(exc)

        return self._to_dict(result)

    def _upload(self, apk_path: str) -> str:
        """Upload APK to MobSF and return the file hash."""
        with open(apk_path, "rb") as f:
            response = requests.post(
                f"{MOBSF_URL}/api/v1/upload",
                files={"file": (Path(apk_path).name, f, "application/octet-stream")},
                headers=self._headers,
                timeout=UPLOAD_TIMEOUT,
            )

        if response.status_code != 200:
            raise MobSFUploadError(
                f"Upload failed: HTTP {response.status_code} — {response.text[:200]}"
            )

        return response.json().get("hash", "")

    def _trigger_scan(self, file_hash: str, file_name: str) -> None:
        """Tell MobSF to scan the uploaded APK."""
        response = requests.post(
            f"{MOBSF_URL}/api/v1/scan",
            data={"hash": file_hash, "file_name": file_name, "re_scan": 0},
            headers=self._headers,
            timeout=SCAN_TIMEOUT,
        )

        if response.status_code != 200:
            raise MobSFScanError(
                f"Scan failed: HTTP {response.status_code} — {response.text[:200]}"
            )

    def _fetch_report(self, file_hash: str) -> dict:
        """Fetch the JSON report from MobSF."""
        response = requests.post(
            f"{MOBSF_URL}/api/v1/report_json",
            data={"hash": file_hash},
            headers=self._headers,
            timeout=REPORT_TIMEOUT,
        )

        if response.status_code != 200:
            raise MobSFScanError(
                f"Report fetch failed: HTTP {response.status_code}"
            )

        return response.json()

    def _parse_report(self, result: MobSFResult, report: dict) -> None:
        """Extract key security fields from MobSF's full report."""
        result.security_score = report.get("security_score", 0)
        result.average_cvss = report.get("average_cvss", 0.0)

        severity = report.get("severity_summary", {})
        result.severity_high = severity.get("high", 0)
        result.severity_warning = severity.get("warning", 0)
        result.severity_info = severity.get("info", 0)

        # Only keep HIGH severity code findings to avoid noise
        code_analysis = report.get("code_analysis", {}).get("findings", {})
        result.code_analysis_high = [
            {"title": k, "description": v.get("metadata", {}).get("description", "")}
            for k, v in code_analysis.items()
            if v.get("severity", "").lower() == "high"
        ][:20]  # Cap at 20 to keep JSON manageable

        result.permissions = list(report.get("permissions", {}).keys())[:30]

    def _write_skipped_result(self, reason: str = "MOBSF_ENABLED not set") -> None:
        write_json(
            f"{OUTPUT_DIR}/results.json",
            {
                "skipped": True,
                "skip_reason": reason,
                "mobsf_enabled": False,
                "results": [],
            },
        )
        self.logger.info(f"Saved stub → {OUTPUT_DIR}/results.json")

    def _save(self, results: list[dict]) -> None:
        write_json(
            f"{OUTPUT_DIR}/results.json",
            {
                "mobsf_enabled": True,
                "mobsf_url": MOBSF_URL,
                "total_analyzed": len(results),
                "results": results,
            },
        )
        self.logger.info(f"Saved → {OUTPUT_DIR}/results.json")

    @staticmethod
    def _to_dict(r: MobSFResult) -> dict:
        return {
            "package_name": r.package_name,
            "apk_path": r.apk_path,
            "file_name": r.file_name,
            "hash": r.hash,
            "security_score": r.security_score,
            "average_cvss": r.average_cvss,
            "severity_high": r.severity_high,
            "severity_warning": r.severity_warning,
            "severity_info": r.severity_info,
            "permissions": r.permissions,
            "code_analysis_high": r.code_analysis_high,
            "skipped": r.skipped,
            "skip_reason": r.skip_reason,
            "error": r.error,
        }
