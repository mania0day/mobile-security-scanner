CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    serial TEXT UNIQUE NOT NULL,
    platform TEXT NOT NULL, -- 'android' | 'ios'
    manufacturer TEXT,
    model TEXT,
    os_version TEXT,
    sdk_version TEXT,
    security_patch TEXT,
    -- Extended device identity
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
    sim_operator TEXT,
    sim_operator_numeric TEXT,
    sim_serial TEXT,
    subscriber_id TEXT,
    screen_lock_enabled INTEGER,
    encryption_enabled INTEGER,
    first_scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    scan_mode TEXT NOT NULL, -- 'minimal' | 'deep'
    verdict TEXT NOT NULL, -- 'PASS' | 'CONDITIONAL' | 'FAIL'
    overall_score INTEGER NOT NULL,
    device_risk_level TEXT NOT NULL,
    total_apps_scanned INTEGER DEFAULT 0,
    critical_apps_count INTEGER DEFAULT 0,
    high_apps_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS checklist_evaluations (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    category TEXT NOT NULL, -- 'identity' | 'root_jailbreak' | 'lock_encryption' | 'installed_apps' | 'network' | 'certificates' | 'management' | 'backup'
    check_name TEXT NOT NULL,
    priority TEXT NOT NULL, -- 'Must' | 'Should' | 'Nice to have'
    status TEXT NOT NULL, -- 'PASS' | 'FAIL' | 'WARNING'
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

CREATE INDEX IF NOT EXISTS idx_scan_sessions_device ON scan_sessions(device_id);
CREATE INDEX IF NOT EXISTS idx_checklist_scan ON checklist_evaluations(scan_id);
CREATE INDEX IF NOT EXISTS idx_app_findings_scan ON app_findings(scan_id);
