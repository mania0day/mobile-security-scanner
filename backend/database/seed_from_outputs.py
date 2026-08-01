#!/usr/bin/env python3
"""
Re-evaluate existing scanner JSON outputs and seed SQLite with meaningful results.
Also regenerates the latest PDF admission certificate.

Usage:
    python backend/database/seed_from_outputs.py
"""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))
sys.path.insert(0, str(PROJECT_ROOT / "services" / "risk_engine" / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "services" / "report_generator" / "src"))

from database.db import init_db, save_scan_results, get_all_scans, get_stats
from evaluator import ChecklistEvaluator


OUTPUT = PROJECT_ROOT / "backend" / "output"


def _load(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def main():
    init_db()
    device = _load(OUTPUT / "adb" / "device.json") or {}
    root = _load(OUTPUT / "root_detection" / "results.json")
    cert = _load(OUTPUT / "certificate" / "results.json")
    perms = _load(OUTPUT / "permission_analyzer" / "results.json")
    yara = _load(OUTPUT / "yara" / "results.json")
    apkid = _load(OUTPUT / "apkid" / "results.json")
    risk = _load(OUTPUT / "risk_engine" / "risk_assessment.json") or {}
    cve = _load(OUTPUT / "cve_checker" / "results.json") or None

    if not device.get("serial") and not risk.get("app_risks"):
        print("No scan outputs found under backend/output — nothing to seed.")
        sys.exit(1)

    app_risks = risk.get("app_risks") or []
    # Ensure yara_severities exists for evaluator
    for a in app_risks:
        a.setdefault("yara_severities", {})
        a.setdefault("apkid_flags", a.get("apkid_flags") or [])
        a.setdefault("critical_permissions", a.get("critical_permissions") or [])
        a.setdefault("cert_issues", a.get("cert_issues") or [])
        a.setdefault("risk_factors", a.get("risk_factors") or [])

    evaluator = ChecklistEvaluator()
    verdict, checklist = evaluator.evaluate(
        device_info=device,
        root_data=root,
        jailbreak_data=None,
        cert_data=cert,
        perm_data=perms,
        yara_data=yara,
        apkid_data=apkid,
        app_risks=app_risks,
        platform="android",
    )

    overall_score = int(risk.get("overall_score") or 0)
    overall_level = risk.get("overall_level") or "LOW"
    scan_mode = risk.get("scan_mode") or "minimal"
    scan_id = f"scan_{uuid.uuid4().hex[:12]}"

    # Appends a new scan row for the device — existing reports are preserved.
    save_scan_results(
        scan_id=scan_id,
        device_info=device,
        scan_mode=scan_mode,
        verdict=verdict,
        overall_score=overall_score,
        device_risk_level=overall_level,
        checklist=checklist,
        app_risks=app_risks,
        cve_findings=cve,
        platform="android",
    )

    # Refresh risk_assessment.json with corrected device + checklist (best-effort)
    risk_out = {
        **risk,
        "device_serial": device.get("serial", ""),
        "verdict": verdict,
        "checklist_evaluations": checklist,
        "scan_mode": scan_mode,
    }
    risk_path = OUTPUT / "risk_engine" / "risk_assessment.json"
    risk_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        risk_path.write_text(json.dumps(risk_out, indent=2))
    except PermissionError:
        print(f"Warning: could not update {risk_path} (permission denied)")

    report_payload = {
        "scan_timestamp": risk.get("scan_timestamp") or "",
        "device_serial": device.get("serial", ""),
        "device": device,
        "scan_mode": scan_mode,
        "verdict": verdict,
        "overall_score": overall_score,
        "overall_level": overall_level,
        "checklist_evaluations": checklist,
        "cve_findings": cve,
        "summary": risk.get("summary") or {
            "total_apps_analyzed": len(app_risks),
            "critical_apps": sum(1 for a in app_risks if a.get("risk_level") == "CRITICAL"),
            "high_apps": sum(1 for a in app_risks if a.get("risk_level") == "HIGH"),
        },
        "device_risk": risk.get("device_risk") or {},
        "app_risks": app_risks,
        "top_risky_apps": sorted(app_risks, key=lambda x: x.get("risk_score", 0), reverse=True)[:10],
    }

    reports_dir = OUTPUT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    try:
        (reports_dir / "report.json").write_text(json.dumps(report_payload, indent=2))
    except PermissionError:
        print(f"Warning: could not update report.json (permission denied)")

    pdf_latest = reports_dir / "report.pdf"
    pdf_scan = reports_dir / f"{scan_id}.pdf"
    try:
        from pdf_generator import generate_pdf_report
        generate_pdf_report(report_payload, str(pdf_scan))
        print(f"PDF written → {pdf_scan}")
        try:
            generate_pdf_report(report_payload, str(pdf_latest))
            print(f"PDF written → {pdf_latest}")
        except PermissionError:
            print(f"Warning: could not overwrite {pdf_latest}")
    except Exception as exc:
        print(f"PDF generation skipped ({exc}). Install reportlab: pip install reportlab")

    stats = get_stats()
    scans = get_all_scans()
    print(f"Seeded scan_id={scan_id}")
    print(f"Device: {device.get('manufacturer')} {device.get('model')} ({device.get('serial')})")
    print(f"Verdict: {verdict} | Score: {overall_score} | Checklist items: {len(checklist)}")
    print(f"DB stats: {stats}")
    if scans:
        print(f"Latest scan row: {scans[0]['id']} → {scans[0]['verdict']}")


if __name__ == "__main__":
    main()
