import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = os.environ.get("DB_PATH", str(PROJECT_ROOT / "backend" / "output" / "mobile_security.db"))


def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


_DEVICE_COLUMNS = {
    "build_id": "TEXT",
    "fingerprint": "TEXT",
    "hardware": "TEXT",
    "bootloader": "TEXT",
    "radio_version": "TEXT",
    "wifi_mac": "TEXT",
    "bluetooth_mac": "TEXT",
    "imei": "TEXT",
    "imei_slot2": "TEXT",
    "meid": "TEXT",
    "phone_number": "TEXT",
    "phone_number_slot2": "TEXT",
    "sim_operator": "TEXT",
    "sim_operator_slot2": "TEXT",
    "sim_operator_numeric": "TEXT",
    "sim_serial": "TEXT",
    "sim_serial_slot2": "TEXT",
    "subscriber_id": "TEXT",
    "subscriber_id_slot2": "TEXT",
    "screen_lock_enabled": "INTEGER",
    "encryption_enabled": "INTEGER",
}
_SCAN_COLUMNS = {
    "total_apps_scanned": "INTEGER DEFAULT 0",
    "critical_apps_count": "INTEGER DEFAULT 0",
    "high_apps_count": "INTEGER DEFAULT 0",
    "cve_findings_json": "TEXT",
}


def _migrate(conn):
    """Add columns that were introduced after the DB file was first created."""
    for table, cols in (("devices", _DEVICE_COLUMNS), ("scan_sessions", _SCAN_COLUMNS)):
        try:
            existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        except sqlite3.Error:
            continue
        for name, ddl in cols.items():
            if name not in existing:
                try:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
                except sqlite3.Error:
                    pass


def init_db():
    conn = get_db_connection()
    schema_path = Path(__file__).resolve().parent / "schema.sql"
    if schema_path.exists():
        conn.executescript(schema_path.read_text())
    else:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            serial TEXT UNIQUE NOT NULL,
            platform TEXT NOT NULL,
            manufacturer TEXT,
            model TEXT,
            os_version TEXT,
            sdk_version TEXT,
            security_patch TEXT,
            build_id TEXT,
            fingerprint TEXT,
            hardware TEXT,
            bootloader TEXT,
            radio_version TEXT,
            wifi_mac TEXT,
            bluetooth_mac TEXT,
            imei TEXT,
            imei_slot2 TEXT,
            meid TEXT,
            phone_number TEXT,
            phone_number_slot2 TEXT,
            sim_operator TEXT,
            sim_operator_slot2 TEXT,
            sim_operator_numeric TEXT,
            sim_serial TEXT,
            sim_serial_slot2 TEXT,
            subscriber_id TEXT,
            subscriber_id_slot2 TEXT,
            screen_lock_enabled INTEGER,
            encryption_enabled INTEGER,
            first_scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS scan_sessions (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            scan_mode TEXT NOT NULL,
            verdict TEXT NOT NULL,
            overall_score INTEGER NOT NULL,
            device_risk_level TEXT NOT NULL,
            total_apps_scanned INTEGER DEFAULT 0,
            critical_apps_count INTEGER DEFAULT 0,
            high_apps_count INTEGER DEFAULT 0,
            cve_findings_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(device_id) REFERENCES devices(id)
        );
        CREATE TABLE IF NOT EXISTS checklist_evaluations (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            category TEXT NOT NULL,
            check_name TEXT NOT NULL,
            priority TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT,
            FOREIGN KEY(scan_id) REFERENCES scan_sessions(id)
        );
        CREATE TABLE IF NOT EXISTS app_findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            package_name TEXT NOT NULL,
            app_name TEXT,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            risk_factors_json TEXT,
            apkid_findings_json TEXT,
            yara_matches_json TEXT,
            critical_permissions_json TEXT,
            cert_issues_json TEXT,
            FOREIGN KEY(scan_id) REFERENCES scan_sessions(id)
        );
        """)
    _migrate(conn)
    conn.commit()
    conn.close()


def save_scan_results(
    scan_id: str,
    device_info: Dict[str, Any],
    scan_mode: str,
    verdict: str,
    overall_score: int,
    device_risk_level: str,
    checklist: List[Dict[str, Any]],
    app_risks: List[Dict[str, Any]],
    cve_findings: Optional[Dict[str, Any]] = None,
    platform: str = "android"
):
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    serial = device_info.get("serial") or device_info.get("udid") or "UNKNOWN_SERIAL"
    manufacturer = device_info.get("manufacturer") or ("Apple" if platform == "ios" else "Unknown")
    model = device_info.get("model") or device_info.get("device_name", "Mobile Device")
    os_version = device_info.get("android_version") or device_info.get("ProductVersion", "")
    sdk_version = str(device_info.get("sdk", ""))
    security_patch = device_info.get("security_patch", "")

    # Extended device fields
    build_id = device_info.get("build_id") or ""
    fingerprint = device_info.get("fingerprint") or ""
    hardware = device_info.get("hardware") or ""
    bootloader = device_info.get("bootloader") or ""
    radio_version = device_info.get("radio_version") or ""
    wifi_mac = device_info.get("wifi_mac") or ""
    bluetooth_mac = device_info.get("bluetooth_mac") or ""
    imei = device_info.get("imei") or ""
    imei_slot2 = device_info.get("imei_slot2") or ""
    meid = device_info.get("meid") or ""
    phone_number = device_info.get("phone_number") or ""
    phone_number_slot2 = device_info.get("phone_number_slot2") or ""
    sim_operator = device_info.get("sim_operator") or ""
    sim_operator_slot2 = device_info.get("sim_operator_slot2") or ""
    sim_operator_numeric = device_info.get("sim_operator_numeric") or ""
    sim_serial = device_info.get("sim_serial") or ""
    sim_serial_slot2 = device_info.get("sim_serial_slot2") or ""
    subscriber_id = device_info.get("subscriber_id") or ""
    subscriber_id_slot2 = device_info.get("subscriber_id_slot2") or ""
    screen_lock_enabled = 1 if device_info.get("screen_lock_enabled") else (0 if device_info.get("screen_lock_enabled") is False else None)
    encryption_enabled = 1 if device_info.get("encryption_enabled") else (0 if device_info.get("encryption_enabled") is False else None)

    # Upsert Device
    cursor.execute("SELECT id FROM devices WHERE serial = ?", (serial,))
    row = cursor.fetchone()
    if row:
        device_id = row["id"]
        cursor.execute("""
            UPDATE devices SET 
                platform = ?, manufacturer = ?, model = ?, 
                os_version = ?, sdk_version = ?, security_patch = ?,
                build_id = ?, fingerprint = ?, hardware = ?, bootloader = ?,
                radio_version = ?, wifi_mac = ?, bluetooth_mac = ?,
                imei = ?, imei_slot2 = ?, meid = ?,
                phone_number = ?, phone_number_slot2 = ?,
                sim_operator = ?, sim_operator_slot2 = ?, sim_operator_numeric = ?,
                sim_serial = ?, sim_serial_slot2 = ?,
                subscriber_id = ?, subscriber_id_slot2 = ?,
                screen_lock_enabled = ?, encryption_enabled = ?,
                last_scanned_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (platform, manufacturer, model, os_version, sdk_version, security_patch,
              build_id, fingerprint, hardware, bootloader,
              radio_version, wifi_mac, bluetooth_mac,
              imei, imei_slot2, meid,
              phone_number, phone_number_slot2,
              sim_operator, sim_operator_slot2, sim_operator_numeric,
              sim_serial, sim_serial_slot2,
              subscriber_id, subscriber_id_slot2,
              screen_lock_enabled, encryption_enabled, device_id))
    else:
        device_id = f"dev_{serial}"
        cursor.execute("""
            INSERT INTO devices
                (id, serial, platform, manufacturer, model, os_version, sdk_version, security_patch,
                 build_id, fingerprint, hardware, bootloader,
                 radio_version, wifi_mac, bluetooth_mac,
                 imei, imei_slot2, meid,
                 phone_number, phone_number_slot2,
                 sim_operator, sim_operator_slot2, sim_operator_numeric,
                 sim_serial, sim_serial_slot2,
                 subscriber_id, subscriber_id_slot2,
                 screen_lock_enabled, encryption_enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?,
                    ?, ?, ?,
                    ?, ?,
                    ?, ?,
                    ?, ?)
        """, (device_id, serial, platform, manufacturer, model, os_version, sdk_version, security_patch,
              build_id, fingerprint, hardware, bootloader,
              radio_version, wifi_mac, bluetooth_mac,
              imei, imei_slot2, meid,
              phone_number, phone_number_slot2,
              sim_operator, sim_operator_slot2, sim_operator_numeric,
              sim_serial, sim_serial_slot2,
              subscriber_id, subscriber_id_slot2,
              screen_lock_enabled, encryption_enabled))

    # Save Scan Session
    critical_apps = sum(1 for a in app_risks if a.get("risk_level") == "CRITICAL")
    high_apps = sum(1 for a in app_risks if a.get("risk_level") == "HIGH")

    cursor.execute("""
        INSERT INTO scan_sessions (id, device_id, scan_mode, verdict, overall_score, device_risk_level, total_apps_scanned, critical_apps_count, high_apps_count, cve_findings_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (scan_id, device_id, scan_mode, verdict, overall_score, device_risk_level, len(app_risks), critical_apps, high_apps,
          json.dumps(cve_findings) if cve_findings else None))

    # Save Checklist Evaluations
    for idx, item in enumerate(checklist):
        chk_id = f"{scan_id}_chk_{idx}"
        cursor.execute("""
            INSERT INTO checklist_evaluations (id, scan_id, category, check_name, priority, status, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            chk_id, scan_id, item.get("category", "General"), item.get("check_name", ""),
            item.get("priority", "Should"), item.get("status", "PASS"), item.get("details", "")
        ))

    # Save App Findings
    for idx, app in enumerate(app_risks):
        app_id = f"{scan_id}_app_{idx}"
        cursor.execute("""
            INSERT INTO app_findings (
                id, scan_id, package_name, app_name, risk_score, risk_level,
                risk_factors_json, apkid_findings_json, yara_matches_json,
                critical_permissions_json, cert_issues_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            app_id, scan_id, app.get("package_name", ""), app.get("package_name", ""),
            app.get("risk_score", 0), app.get("risk_level", "LOW"),
            json.dumps(app.get("risk_factors", [])),
            json.dumps(app.get("apkid_flags", [])),
            json.dumps(app.get("yara_matches", 0)),
            json.dumps(app.get("critical_permissions", [])),
            json.dumps(app.get("cert_issues", []))
        ))

    conn.commit()
    conn.close()


def get_all_scans():
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT s.*, d.serial, d.manufacturer, d.model, d.platform, d.os_version,
               d.imei, d.imei_slot2, d.phone_number, d.phone_number_slot2,
               d.sim_operator, d.sim_operator_slot2, d.sim_serial, d.sim_serial_slot2
        FROM scan_sessions s
        JOIN devices d ON s.device_id = d.id
        ORDER BY s.created_at DESC
    """)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_scan_details(scan_id: str):
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT s.*, d.serial, d.manufacturer, d.model, d.platform, d.os_version, d.sdk_version, d.security_patch,
               d.build_id, d.hardware, d.bootloader, d.radio_version,
               d.imei, d.imei_slot2, d.meid, d.phone_number, d.phone_number_slot2,
               d.sim_operator, d.sim_operator_slot2, d.sim_operator_numeric, d.sim_serial, d.sim_serial_slot2,
               d.subscriber_id, d.subscriber_id_slot2,
               d.screen_lock_enabled, d.encryption_enabled
        FROM scan_sessions s
        JOIN devices d ON s.device_id = d.id
        WHERE s.id = ?
    """, (scan_id,))
    scan = cursor.fetchone()
    if not scan:
        conn.close()
        return None

    scan_dict = dict(scan)
    scan_dict["cve_findings"] = json.loads(scan_dict["cve_findings_json"]) if scan_dict.get("cve_findings_json") else None

    cursor.execute("SELECT * FROM checklist_evaluations WHERE scan_id = ?", (scan_id,))
    scan_dict["checklist"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM app_findings WHERE scan_id = ?", (scan_id,))
    apps = [dict(r) for r in cursor.fetchall()]
    for a in apps:
        a["risk_factors"] = json.loads(a["risk_factors_json"]) if a.get("risk_factors_json") else []
        a["apkid_flags"] = json.loads(a["apkid_findings_json"]) if a.get("apkid_findings_json") else []
        a["critical_permissions"] = json.loads(a["critical_permissions_json"]) if a.get("critical_permissions_json") else []
        a["cert_issues"] = json.loads(a["cert_issues_json"]) if a.get("cert_issues_json") else []
    scan_dict["app_findings"] = apps

    conn.close()
    return scan_dict


def get_all_devices():
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT d.*, 
               (SELECT COUNT(*) FROM scan_sessions WHERE device_id = d.id) as total_scans,
               (SELECT verdict FROM scan_sessions WHERE device_id = d.id ORDER BY created_at DESC LIMIT 1) as last_verdict
        FROM devices d
        ORDER BY d.last_scanned_at DESC
    """)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_device_detail(device_id: str):
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT d.*,
               (SELECT COUNT(*) FROM scan_sessions WHERE device_id = d.id) as total_scans,
               (SELECT verdict FROM scan_sessions WHERE device_id = d.id ORDER BY created_at DESC LIMIT 1) as last_verdict,
               (SELECT created_at FROM scan_sessions WHERE device_id = d.id ORDER BY created_at DESC LIMIT 1) as last_scanned_at
        FROM devices d
        WHERE d.id = ? OR d.serial = ?
    """, (device_id, device_id))
    device = cursor.fetchone()
    if not device:
        conn.close()
        return None
    result = dict(device)
    cursor.execute("""
        SELECT s.*, d.serial, d.manufacturer, d.model, d.platform, d.os_version, d.security_patch
        FROM scan_sessions s
        JOIN devices d ON s.device_id = d.id
        WHERE d.id = ? OR d.serial = ?
        ORDER BY s.created_at DESC
    """, (device_id, device_id))
    result["scans"] = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return result


def get_device_scans(device_id: str):
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT s.*, d.serial, d.manufacturer, d.model, d.platform, d.os_version
        FROM scan_sessions s
        JOIN devices d ON s.device_id = d.id
        WHERE d.id = ? OR d.serial = ?
        ORDER BY s.created_at DESC
    """, (device_id, device_id))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_stats():
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    devices = cursor.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    scans = cursor.execute("SELECT COUNT(*) FROM scan_sessions").fetchone()[0]
    passed = cursor.execute("SELECT COUNT(*) FROM scan_sessions WHERE verdict = 'PASS'").fetchone()[0]
    conditional = cursor.execute("SELECT COUNT(*) FROM scan_sessions WHERE verdict = 'CONDITIONAL'").fetchone()[0]
    failed = cursor.execute("SELECT COUNT(*) FROM scan_sessions WHERE verdict = 'FAIL'").fetchone()[0]
    conn.close()
    return {
        "devices": devices,
        "scans": scans,
        "pass": passed,
        "conditional": conditional,
        "fail": failed,
    }


def clear_all_data():
    """Wipe scan history (used by reseeding)."""
    init_db()
    conn = get_db_connection()
    conn.executescript("""
        DELETE FROM app_findings;
        DELETE FROM checklist_evaluations;
        DELETE FROM scan_sessions;
        DELETE FROM devices;
    """)
    conn.commit()
    conn.close()


def delete_scan(scan_id: str) -> bool:
    """Delete one scan session and its checklist/app rows. Remove orphan devices."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT device_id FROM scan_sessions WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False
    device_id = row["device_id"]
    cursor.execute("DELETE FROM app_findings WHERE scan_id = ?", (scan_id,))
    cursor.execute("DELETE FROM checklist_evaluations WHERE scan_id = ?", (scan_id,))
    cursor.execute("DELETE FROM scan_sessions WHERE id = ?", (scan_id,))
    cursor.execute("SELECT COUNT(*) AS c FROM scan_sessions WHERE device_id = ?", (device_id,))
    remaining = cursor.fetchone()["c"]
    if remaining == 0:
        cursor.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()

    # Best-effort cleanup of generated PDF
    reports = Path(DB_PATH).resolve().parent / "reports"
    for name in (f"{scan_id}.pdf",):
        pdf = reports / name
        if pdf.exists():
            try:
                pdf.unlink()
            except OSError:
                pass
    return True


def delete_device(device_id: str) -> bool:
    """Delete a device and all of its scan history."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM devices WHERE id = ? OR serial = ?", (device_id, device_id))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False
    real_id = row["id"]
    cursor.execute("SELECT id FROM scan_sessions WHERE device_id = ?", (real_id,))
    scan_ids = [r["id"] for r in cursor.fetchall()]
    for sid in scan_ids:
        cursor.execute("DELETE FROM app_findings WHERE scan_id = ?", (sid,))
        cursor.execute("DELETE FROM checklist_evaluations WHERE scan_id = ?", (sid,))
    cursor.execute("DELETE FROM scan_sessions WHERE device_id = ?", (real_id,))
    cursor.execute("DELETE FROM devices WHERE id = ?", (real_id,))
    conn.commit()
    conn.close()

    reports = Path(DB_PATH).resolve().parent / "reports"
    for sid in scan_ids:
        pdf = reports / f"{sid}.pdf"
        if pdf.exists():
            try:
                pdf.unlink()
            except OSError:
                pass
    return True


if __name__ == "__main__":
    init_db()
    print(f"SQLite database initialized at {DB_PATH}")
