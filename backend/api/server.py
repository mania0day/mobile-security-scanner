import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))
sys.path.insert(0, str(PROJECT_ROOT / "backend" / "api"))
sys.path.insert(0, str(PROJECT_ROOT / "services" / "report_generator" / "src"))

from database.db import (
    get_device_detail,
    get_all_scans,
    get_scan_details,
    get_all_devices,
    get_device_scans,
    get_stats,
    init_db,
    delete_scan,
    delete_device,
)
from connected import list_connected_devices
from scan_jobs import start_scan, get_status, cancel_scan, get_logs, LOG_PATH

init_db()

PORT = int(os.environ.get("API_PORT", "5000"))
REPORTS_DIR = PROJECT_ROOT / "backend" / "output" / "reports"
CVE_OUTPUT_FILE = PROJECT_ROOT / "backend" / "output" / "cve_checker" / "results.json"


def _load_cve_output():
    try:
        if CVE_OUTPUT_FILE.exists():
            return json.loads(CVE_OUTPUT_FILE.read_text())
    except Exception:
        pass
    return None


def _pdf_basename(scan: dict) -> str:
    mode = (scan.get("scan_mode") or "minimal").lower().replace(" ", "_")
    if mode not in ("minimal", "deep", "quick"):
        mode = "minimal"
    scan_id = scan.get("id") or "scan"
    serial = (scan.get("serial") or "device").replace("/", "_")[:24]
    return f"admission_{mode}_{serial}_{scan_id}"


SENSITIVE_FIELDS = {
    "serial",
    "imei", "imei_slot2", "meid",
    "phone_number", "phone_number_slot2",
    "subscriber_id", "subscriber_id_slot2",
    "sim_serial", "sim_serial_slot2",
    "wifi_mac", "bluetooth_mac",
}

def _strip_sensitive(data: dict) -> dict:
    """Return a copy of device data with IMEI/phone/SIM fields redacted."""
    out = dict(data)
    for key in list(out.keys()):
        if key in SENSITIVE_FIELDS:
            out[key] = "REDACTED"
    return out


def _ensure_scan_pdf(scan: dict, safe: bool = False, one_pager: bool = False) -> Path | None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    mode = (scan.get("scan_mode") or "minimal").lower()
    if mode not in ("minimal", "deep", "quick"):
        mode = "minimal"
    scan_id = scan["id"]
    base = _pdf_basename(scan)
    suffix = "_safe" if safe else ""
    if one_pager:
        suffix += "_onepager"
    scan_pdf = REPORTS_DIR / f"{base}{suffix}.pdf"
    alias_pdf = REPORTS_DIR / f"{scan_id}_{mode}{suffix}.pdf"

    device = {
        "serial": scan.get("serial"),
        "manufacturer": scan.get("manufacturer"),
        "model": scan.get("model"),
        "android_version": scan.get("os_version"),
        "os_version": scan.get("os_version"),
        "sdk": scan.get("sdk_version"),
        "sdk_version": scan.get("sdk_version"),
        "security_patch": scan.get("security_patch"),
        "platform": scan.get("platform"),
        "build_id": scan.get("build_id"),
        "fingerprint": scan.get("fingerprint"),
        "hardware": scan.get("hardware"),
        "bootloader": scan.get("bootloader"),
        "radio_version": scan.get("radio_version"),
        "imei": scan.get("imei"),
        "imei_slot2": scan.get("imei_slot2"),
        "meid": scan.get("meid"),
        "phone_number": scan.get("phone_number"),
        "phone_number_slot2": scan.get("phone_number_slot2"),
        "sim_operator": scan.get("sim_operator"),
        "sim_operator_slot2": scan.get("sim_operator_slot2"),
        "sim_operator_numeric": scan.get("sim_operator_numeric"),
        "sim_serial": scan.get("sim_serial"),
        "sim_serial_slot2": scan.get("sim_serial_slot2"),
        "subscriber_id": scan.get("subscriber_id"),
        "subscriber_id_slot2": scan.get("subscriber_id_slot2"),
        "screen_lock_enabled": scan.get("screen_lock_enabled"),
        "encryption_enabled": scan.get("encryption_enabled"),
        "bootloader_unlocked": scan.get("bootloader_unlocked"),
        "screen_lock_evidence": scan.get("screen_lock_evidence"),
        "oem_unlock_allowed": scan.get("oem_unlock_allowed"),
    }

    if safe:
        device = _strip_sensitive(device)

    payload = {
        "safe_mode": safe,
        "scan_id": scan.get("id", scan_id),
        "scan_timestamp": scan.get("created_at", ""),
        "device_serial": scan.get("serial", ""),
        "platform": scan.get("platform", "android"),
        "device": device,
        "scan_mode": mode,
        "verdict": scan.get("verdict", "PASS"),
        "severity_tier": scan.get("severity_tier") or "Safe",
        "overall_score": scan.get("overall_score", 0),
        "overall_level": scan.get("device_risk_level", "LOW"),
        "device_risk_level": scan.get("device_risk_level", "LOW"),
        "checklist_evaluations": scan.get("checklist", []),
        "cve_findings": scan.get("cve_findings")
        or _load_cve_output(),
        "summary": {
            "total_apps_analyzed": scan.get("total_apps_scanned", 0),
            "critical_apps": scan.get("critical_apps_count", 0),
            "high_apps": scan.get("high_apps_count", 0),
        },
        "device_risk": scan.get("device_risk")
        or {
            "is_rooted": scan.get("is_rooted", False),
            "bootloader_unlocked": scan.get("bootloader_unlocked", False),
            "oem_unlock_allowed": scan.get("oem_unlock_allowed"),
            "selinux_status": "Unknown",
        },
        "app_risks": [
            {
                "package_name": a.get("package_name"),
                "risk_score": a.get("risk_score", 0),
                "risk_level": a.get("risk_level", "LOW"),
                "risk_factors": a.get("risk_factors", []),
            }
            for a in (scan.get("app_findings") or [])
        ],
    }

    for stale in (scan_pdf, alias_pdf, REPORTS_DIR / f"{scan_id}_{mode}.pdf"):
        try:
            if stale.exists():
                stale.unlink()
        except OSError:
            pass

    try:
        if one_pager:
            from pdf_generator import generate_one_pager_report
            generate_one_pager_report(payload, str(scan_pdf))
        else:
            from pdf_generator import generate_pdf_report
            generate_pdf_report(payload, str(scan_pdf))
        try:
            (generate_one_pager_report if one_pager else generate_pdf_report)(payload, str(alias_pdf))
        except OSError:
            pass
        return scan_pdf
    except Exception as exc:
        print(f"PDF generation failed: {exc}")
        if alias_pdf.exists():
            return alias_pdf
        fallback = REPORTS_DIR / "report.pdf"
        return fallback if fallback.exists() else None


class APIHandler(BaseHTTPRequestHandler):
    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/api/health":
            self._send_json({"status": "ok", "service": "Mobile Security Scanner API"})
            return

        if path == "/api/scan/status":
            self._send_json(get_status())
            return

        if path == "/api/scan/logs":
            limit_q = parsed.query or ""
            try:
                limit = int([p.split("=")[1] for p in limit_q.split("&") if p.startswith("limit=")][0])
            except (IndexError, ValueError):
                limit = 150
            self._send_json({"logs": get_logs(limit)})
            return

        if path == "/api/stats":
            self._send_json({"stats": get_stats()})
            return

        if path == "/api/connected":
            devices = list_connected_devices()
            self._send_json({
                "devices": devices,
                "count": len(devices),
                "ready_count": sum(1 for d in devices if d.get("ready")),
            })
            return

        if path == "/api/scans":
            self._send_json({"scans": get_all_scans()})
            return

        if path == "/api/devices":
            self._send_json({"devices": get_all_devices()})
            return

        if path.startswith("/api/devices/"):
            parts = [p for p in path.split("/") if p]
            device_id = parts[2]
            if len(parts) > 3 and parts[3] == "scans":
                scans = get_device_scans(device_id)
                self._send_json({"device_id": device_id, "scans": scans})
            else:
                detail = get_device_detail(device_id)
                if not detail:
                    self._send_json({"error": "Device not found"}, status=404)
                    return
                self._send_json({"device": detail})
            return

        if path.startswith("/api/scans/"):
            parts = [p for p in path.split("/") if p]
            scan_id = parts[2]
            details = get_scan_details(scan_id)
            if not details:
                self._send_json({"error": "Scan not found"}, status=404)
                return
            if len(parts) > 3 and parts[3] == "pdf":
                safe = parsed.query == "safe=true" or parts[2].endswith("_safe")
                one_pager = len(parts) > 4 and parts[4] == "one-pager"
                if parsed.query == "format=one-pager":
                    one_pager = True
                pdf_path = _ensure_scan_pdf(details, safe=safe, one_pager=one_pager)
                if not pdf_path or not pdf_path.exists():
                    self._send_json({"error": "PDF report not available"}, status=404)
                    return
                fname = _pdf_basename(details)
                if safe:
                    fname += "_safe"
                self.send_response(200)
                self._send_cors_headers()
                self.send_header("Content-Type", "application/pdf")
                self.send_header(
                    "Content-Disposition",
                    f'attachment; filename="{fname}.pdf"',
                )
                self.end_headers()
                with open(pdf_path, "rb") as f:
                    self.wfile.write(f.read())
                return
            self._send_json({"scan": details})
            return

        if path == "/api/reports/pdf":
            pdf_path = REPORTS_DIR / "report.pdf"
            if not pdf_path.exists():
                scans = get_all_scans()
                if scans:
                    details = get_scan_details(scans[0]["id"])
                    if details:
                        pdf_path = _ensure_scan_pdf(details) or pdf_path
            if pdf_path and Path(pdf_path).exists():
                self.send_response(200)
                self._send_cors_headers()
                self.send_header("Content-Type", "application/pdf")
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="mobile_security_admission_report.pdf"',
                )
                self.end_headers()
                with open(pdf_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self._send_json({"error": "PDF report file not found"}, status=404)
            return

        self._send_json({"error": "Endpoint not found"}, status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/scan/start":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
            try:
                body = json.loads(post_body)
            except Exception:
                body = {}

            mode = body.get("mode", "minimal")
            if mode not in ("minimal", "deep", "quick"):
                mode = "minimal"
            platform = body.get("platform", "auto")
            serial = str(body.get("serial") or "").strip()
            vt_enabled = bool(body.get("vt_enabled")) and mode == "deep"
            cmd = [
                sys.executable,
                str(PROJECT_ROOT / "backend" / "orchestrator" / "orchestrator.py"),
                "--mode", mode,
                "--platform", platform,
            ]
            if vt_enabled:
                cmd.append("--vt")
            if serial:
                cmd.extend(["--serial", serial])
            result = start_scan(cmd, mode=mode, platform=platform, cwd=str(PROJECT_ROOT))
            status_code = 409 if result.get("status") == "busy" else 200
            self._send_json(result, status=status_code)
            return

        if path == "/api/scan/cancel":
            self._send_json(cancel_scan())
            return

        self._send_json({"error": "Endpoint not found"}, status=404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        parts = [p for p in path.split("/") if p]

        if len(parts) == 3 and parts[0] == "api" and parts[1] == "scans":
            ok = delete_scan(parts[2])
            if ok:
                self._send_json({"status": "deleted", "id": parts[2]})
            else:
                self._send_json({"error": "Scan not found"}, status=404)
            return

        if len(parts) == 3 and parts[0] == "api" and parts[1] == "devices":
            ok = delete_device(parts[2])
            if ok:
                self._send_json({"status": "deleted", "id": parts[2]})
            else:
                self._send_json({"error": "Device not found"}, status=404)
            return

        self._send_json({"error": "Endpoint not found"}, status=404)

    def _send_json(self, data, status=200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def run_server():
    server = HTTPServer(("0.0.0.0", PORT), APIHandler)
    print(f"Mobile Security Scanner API running at http://localhost:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    run_server()
