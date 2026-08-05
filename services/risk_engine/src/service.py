import os
import sys
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pathlib import Path

from shared.json_writer import read_json, write_json
from shared.logger import get_logger

from config import (
    OUTPUT_BASE, ADB_OUTPUT, APKID_OUTPUT, ANDROGUARD_OUTPUT,
    MOBSF_OUTPUT, CERTIFICATE_OUTPUT, PERMISSION_OUTPUT,
    ROOT_OUTPUT, HASH_OUTPUT, YARA_OUTPUT, MVT_OUTPUT,
    CVE_OUTPUT, OUTPUT_DIR,
)
from models import AppRisk, DeviceRisk, RiskAssessment
from weights import APP_WEIGHTS, DEVICE_WEIGHTS, score_to_level
from evaluator import ChecklistEvaluator

try:
    _repo_root = Path(__file__).resolve().parents[3]
    for base in (Path("/app/backend"), _repo_root / "backend"):
        if (base / "database" / "db.py").exists():
            sys.path.insert(0, str(base))
            break
    from database.db import save_scan_results
except Exception:
    save_scan_results = None


class RiskEngineService:
    """
    Aggregates all service outputs, evaluates the admission checklist (Mobile_Device_Security_Scan_Checklist.docx),
    and persists findings to SQLite database and risk_assessment.json.
    """

    def __init__(self):
        self.logger = get_logger("RiskEngine")
        self.evaluator = ChecklistEvaluator()
        self.cve_findings = None

    def run(self) -> None:
        self.logger.info("Starting Risk Engine")

        device = self._load_safe(f"{ADB_OUTPUT}/device.json", "adb")
        ios_device = self._load_safe(f"{OUTPUT_BASE}/ios_device/device.json", "ios_device")

        # Prefer a connected Android device; ignore stale iOS stubs (is_connected=false / empty udid).
        ios_connected = bool(
            ios_device
            and ios_device.get("is_connected", True)
            and (ios_device.get("udid") or ios_device.get("serial"))
        )
        android_connected = bool(device and (device.get("serial") or device.get("model")))

        if android_connected:
            platform = "android"
            dev_info = device or {}
        elif ios_connected:
            platform = "ios"
            dev_info = ios_device or {}
        else:
            platform = "ios" if ios_device and not device else "android"
            dev_info = (ios_device if platform == "ios" else device) or {}

        serial = dev_info.get("serial") or dev_info.get("udid") or "unknown"

        # Load all service outputs safely
        root = self._load_safe(f"{ROOT_OUTPUT}/results.json", "root_detection")
        jailbreak = self._load_safe("/app/backend/output/jailbreak_detection/results.json", "jailbreak_detection")
        apkid = self._load_safe(f"{APKID_OUTPUT}/results.json", "apkid")
        androguard = self._load_safe(f"{ANDROGUARD_OUTPUT}/results.json", "androguard")
        cert = self._load_safe(f"{CERTIFICATE_OUTPUT}/results.json", "certificate")
        perms = self._load_safe(f"{PERMISSION_OUTPUT}/results.json", "permission_analyzer")
        hashes = self._load_safe(f"{HASH_OUTPUT}/results.json", "hash_lookup")
        yara = self._load_safe(f"{YARA_OUTPUT}/results.json", "yara")
        mobsf = self._load_safe(f"{MOBSF_OUTPUT}/results.json", "mobsf")
        mvt = self._load_safe(f"{MVT_OUTPUT}/results.json", "mvt")
        cve = self._load_safe(f"{CVE_OUTPUT}/results.json", "cve_checker")
        self.cve_findings = cve

        # Build lookup tables
        apkid_map = self._index_by_package(apkid, "results")
        cert_map = self._index_by_package(cert, "results")
        perm_map = self._index_by_package(perms, "results")
        hash_map = self._index_by_package(hashes, "results")
        yara_map = self._index_by_package(yara, "results")
        mobsf_map = self._index_by_package(mobsf, "results")

        all_packages = set()
        for res_dict in (androguard, apkid, cert, perms, hashes, yara, mobsf):
            if res_dict and isinstance(res_dict, dict):
                for r in res_dict.get("results", []):
                    if isinstance(r, dict) and r.get("package_name"):
                        all_packages.add(r["package_name"])

        # Score each app
        app_risks: list[AppRisk] = []
        for pkg in sorted(all_packages):
            app_risk = self._score_app(
                pkg, apkid_map, cert_map, perm_map,
                hash_map, yara_map, mobsf_map
            )
            app_risks.append(app_risk)

        # Score the device
        device_risk = self._score_device(serial, root)

        # overall_score represents the WHOLE DEVICE's risk, not one outlier
        # app. Weights above are documented as "out of 100, then averaged
        # across all apps" but this used to take max() of every app's score
        # instead — so on a real phone with 400+ apps, a single app's raw
        # additive permission/YARA score (easy to rack up legitimately: e.g.
        # Google Play Services needs a dozen permissions to broker services
        # for other apps) silently overrode every other app and pinned the
        # entire device to 100/CRITICAL. Use the population average, matching
        # the documented intent — individually concerning apps are still
        # called out by name in the checklist below (high_risk_apps /
        # malware_pkgs), they just no longer dominate the device-wide gauge.
        avg_app_score = round(sum(a.risk_score for a in app_risks) / len(app_risks)) if app_risks else 0
        overall_score = max(device_risk.risk_score, avg_app_score)

        critical_apps = sum(1 for a in app_risks if a.risk_level == "CRITICAL")
        high_apps = sum(1 for a in app_risks if a.risk_level == "HIGH")

        scan_mode_override = (os.environ.get("SCAN_MODE") or "").strip().lower()
        scan_mode = self._determine_scan_mode(mobsf, mvt, scan_mode_override)

        # Checklist Evaluation (Mobile_Device_Security_Scan_Checklist.docx)
        verdict, checklist, severity_tier = self.evaluator.evaluate(
            device_info=dev_info,
            root_data=root,
            jailbreak_data=jailbreak,
            cert_data=cert,
            perm_data=perms,
            yara_data=yara,
            apkid_data=apkid,
            app_risks=app_risks,
            platform=platform,
            scan_mode=scan_mode,
            mvt_data=mvt,
            cve_data=cve,
        )

        assessment = RiskAssessment(
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            device_serial=serial,
            scan_mode=scan_mode,
            device_risk=device_risk,
            overall_score=overall_score,
            overall_level=score_to_level(overall_score),
            total_apps_analyzed=len(app_risks),
            critical_apps=critical_apps,
            high_apps=high_apps,
            app_risks=app_risks,
            services_ran=self._services_ran(root, apkid, androguard, cert, perms, hashes, yara, mobsf, mvt),
            services_skipped=self._services_skipped(mobsf, mvt),
        )

        # Save JSON output
        self._save(assessment, verdict, checklist, severity_tier)

        # Save to SQLite Database
        scan_id = f"scan_{uuid.uuid4().hex[:12]}"
        device_risk_dict = {
            "serial": device_risk.serial,
            "risk_score": device_risk.risk_score,
            "risk_level": device_risk.risk_level,
            "risk_factors": device_risk.risk_factors,
            "is_rooted": device_risk.is_rooted,
            "selinux_status": device_risk.selinux_status,
            "is_debuggable": device_risk.is_debuggable,
            "bootloader_unlocked": device_risk.bootloader_unlocked,
            "oem_unlock_allowed": device_risk.oem_unlock_allowed,
        }
        if save_scan_results:
            try:
                save_scan_results(
                    scan_id=scan_id,
                    device_info=dev_info,
                    scan_mode=scan_mode,
                    verdict=verdict,
                    overall_score=overall_score,
                    device_risk_level=score_to_level(overall_score),
                    checklist=checklist,
                    app_risks=[a.__dict__ for a in app_risks],
                    cve_findings=cve,
                    platform=platform,
                    device_risk=device_risk_dict,
                    severity_tier=severity_tier,
                )
                self.logger.info(f"Persisted scan {scan_id} to SQLite database")
            except Exception as e:
                self.logger.warning(f"Could not persist to SQLite database: {e}")

        self.logger.info(
            f"Risk Engine finished — Verdict: {verdict}, overall score: {overall_score} "
            f"({score_to_level(overall_score)})"
        )

    def _score_device(self, serial: str, root: dict | None) -> DeviceRisk:
        dr = DeviceRisk(serial=serial)
        if not root:
            return dr

        score = 0
        factors = []
        checks = root.get("checks", {})

        # Collect every root signal that fired for display/transparency, but only
        # add the "rooted" weight ONCE — previously each of these three checks
        # independently added the full weight, letting a single rooted device
        # stack up to 75 points from "rootedness" alone.
        root_signals = []
        if checks.get("su_binary_found"):
            root_signals.append("Root binary (su) detected")
        if checks.get("su_execution_confirmed"):
            root_signals.append(f"Root access confirmed via su execution (uid=0): {checks.get('su_execution_output', '')}")
        if checks.get("magisk_detected"):
            root_signals.append("Magisk root framework detected")
        if checks.get("root_manager_detected"):
            root_signals.append("Root manager application installed")
        magisk_ind = checks.get("magisk_indicators") or {}
        fired_ind = [k for k, v in magisk_ind.items() if v]
        if fired_ind:
            root_signals.append(f"Modern Magisk artifacts detected ({', '.join(fired_ind)})")
        if checks.get("overlay_mounts_found"):
            root_signals.append("OverlayFS mount detected (systemless root indicator)")

        if root_signals:
            score += DEVICE_WEIGHTS["rooted"]
            factors.extend(root_signals)
            dr.is_rooted = True

        if checks.get("ro_secure") == "0":
            score += DEVICE_WEIGHTS["ro_secure"]
            factors.append("ro.secure=0 — unrestricted ADB root shell")

        if checks.get("bootloader_unlocked"):
            score += DEVICE_WEIGHTS["bootloader_unlocked"]
            factors.append("Bootloader is unlocked / verified boot not enforcing")
            dr.bootloader_unlocked = True

        dr.oem_unlock_allowed = checks.get("oem_unlock_allowed")

        selinux = root.get("checks", {}).get("selinux_status", "")
        dr.selinux_status = selinux
        if selinux and selinux.lower() != "enforcing":
            score += DEVICE_WEIGHTS["selinux_permissive"]
            factors.append(f"SELinux is {selinux} (expected: Enforcing)")

        if root.get("checks", {}).get("is_debuggable_build"):
            score += DEVICE_WEIGHTS["debuggable_build"]
            factors.append("Device is running a debuggable build")
            dr.is_debuggable = True

        if root.get("checks", {}).get("is_test_keys"):
            score += DEVICE_WEIGHTS["test_keys"]
            factors.append("ROM built with test-keys (not production signed)")

        dr.risk_score = min(score, 100)
        dr.risk_level = score_to_level(dr.risk_score)
        dr.risk_factors = factors
        return dr

    def _score_app(
        self,
        package_name: str,
        apkid_map: dict,
        cert_map: dict,
        perm_map: dict,
        hash_map: dict,
        yara_map: dict,
        mobsf_map: dict,
    ) -> AppRisk:
        risk = AppRisk(package_name=package_name)
        score = 0

        # YARA
        yara_result = yara_map.get(package_name, {})
        for match in yara_result.get("matches", []):
            severity = match.get("severity", "low").lower()
            w = APP_WEIGHTS.get(f"yara_{severity}", 5)
            score += w
            risk.yara_matches += 1
            risk.yara_severities[severity] = risk.yara_severities.get(severity, 0) + 1
            risk.risk_factors.append(f"YARA: {match.get('rule')} ({severity})")

        # Certificate
        cert_result = cert_map.get(package_name, {})
        cert_flags = cert_result.get("risk_flags") or {}
        if cert_flags.get("is_expired"):
            score += APP_WEIGHTS["cert_expired"]
            risk.cert_issues.append("expired")
            risk.risk_factors.append("Certificate is expired")
        if cert_flags.get("uses_weak_algorithm"):
            score += APP_WEIGHTS["cert_weak_algorithm"]
            risk.cert_issues.append("weak_algorithm")
            risk.risk_factors.append("Weak signing algorithm (MD5/SHA1)")

        # Permissions
        perm_result = perm_map.get(package_name, {})
        risk_summary = perm_result.get("risk_summary", {})
        critical_count = risk_summary.get("critical", 0)
        high_count = risk_summary.get("high", 0)
        medium_count = risk_summary.get("medium", 0)

        score += critical_count * APP_WEIGHTS["permission_critical"]
        score += high_count * APP_WEIGHTS["permission_high"]
        score += medium_count * APP_WEIGHTS["permission_medium"]

        if critical_count:
            risk.risk_factors.append(f"{critical_count} critical-risk permission(s)")
        if high_count:
            risk.risk_factors.append(f"{high_count} high-risk permission(s)")

        risk.critical_permissions = [
            p["permission"] for p in perm_result.get("dangerous_permissions", [])
            if p.get("risk") == "critical"
        ]
        risk.high_permissions = [
            p["permission"] for p in perm_result.get("dangerous_permissions", [])
            if p.get("risk") == "high"
        ]

        # APKID
        apkid_result = apkid_map.get(package_name, {})
        findings = apkid_result.get("findings", {})
        if findings.get("obfuscator"):
            score += APP_WEIGHTS["apkid_obfuscator"]
            risk.apkid_flags.extend(findings["obfuscator"])
            risk.risk_factors.append(f"Obfuscation: {', '.join(findings['obfuscator'])}")
        if findings.get("packer"):
            score += APP_WEIGHTS["apkid_packer"]
            risk.apkid_flags.extend(findings["packer"])
            risk.risk_factors.append("Packer detected")

        risk.risk_score = min(score, 100)
        risk.risk_level = score_to_level(risk.risk_score)
        return risk

    def _load_safe(self, path: str, service_name: str) -> dict | None:
        if not Path(path).exists():
            self.logger.warning(f"{service_name} output not found at {path} — skipping")
            return None
        try:
            return read_json(path)
        except Exception as exc:
            self.logger.error(f"Failed to read {path}: {exc}")
            return None

    @staticmethod
    def _index_by_package(data: dict | None, key: str) -> dict:
        if not data:
            return {}
        return {r["package_name"]: r for r in data.get(key, []) if isinstance(r, dict) and "package_name" in r}

    @staticmethod
    def _determine_scan_mode(mobsf: dict | None, mvt: dict | None, scan_mode_override: str | None = None) -> str:
        if scan_mode_override in {"deep", "minimal", "quick"}:
            return scan_mode_override
        if (mobsf and not mobsf.get("skipped")) or (mvt and not mvt.get("skipped")):
            return "deep"
        return "minimal"

    @staticmethod
    def _services_ran(*results) -> list[str]:
        names = ["root_detection", "apkid", "androguard", "certificate", "permission_analyzer", "hash_lookup", "yara", "mobsf", "mvt"]
        return [name for name, r in zip(names, results) if r and not r.get("skipped")]

    @staticmethod
    def _services_skipped(*results) -> list[str]:
        names = ["root_detection", "apkid", "androguard", "certificate", "permission_analyzer", "hash_lookup", "yara", "mobsf", "mvt"]
        return [name for name, r in zip(names, results) if not r or r.get("skipped")]

    def _save(self, assessment: RiskAssessment, verdict: str, checklist: List[Dict[str, Any]], severity_tier: str = "Safe") -> None:
        payload = {
            "scan_timestamp": assessment.scan_timestamp,
            "device_serial": assessment.device_serial,
            "scan_mode": assessment.scan_mode,
            "verdict": verdict,
            "severity_tier": severity_tier,
            "overall_score": assessment.overall_score,
            "overall_level": assessment.overall_level,
            "checklist_evaluations": checklist,
            "cve_findings": self.cve_findings or None,
            "services_ran": assessment.services_ran,
            "services_skipped": assessment.services_skipped,
            "device_risk": {
                "serial": assessment.device_risk.serial,
                "risk_score": assessment.device_risk.risk_score,
                "risk_level": assessment.device_risk.risk_level,
                "risk_factors": assessment.device_risk.risk_factors,
                "is_rooted": assessment.device_risk.is_rooted,
                "selinux_status": assessment.device_risk.selinux_status,
                "is_debuggable": assessment.device_risk.is_debuggable,
                "bootloader_unlocked": assessment.device_risk.bootloader_unlocked,
                "oem_unlock_allowed": assessment.device_risk.oem_unlock_allowed,
            },
            "summary": {
                "total_apps_analyzed": assessment.total_apps_analyzed,
                "critical_apps": assessment.critical_apps,
                "high_apps": assessment.high_apps,
                "medium_apps": sum(1 for a in assessment.app_risks if a.risk_level == "MEDIUM"),
                "low_apps": sum(1 for a in assessment.app_risks if a.risk_level == "LOW"),
            },
            "app_risks": [
                {
                    "package_name": a.package_name,
                    "risk_score": a.risk_score,
                    "risk_level": a.risk_level,
                    "risk_factors": a.risk_factors,
                    "yara_matches": a.yara_matches,
                    "cert_issues": a.cert_issues,
                    "critical_permissions": a.critical_permissions,
                    "high_permissions": a.high_permissions,
                    "apkid_flags": a.apkid_flags,
                    "vt_malicious": a.vt_malicious,
                    "mobsf_score": a.mobsf_score,
                }
                for a in sorted(assessment.app_risks, key=lambda x: x.risk_score, reverse=True)
            ],
        }

        write_json(f"{OUTPUT_DIR}/risk_assessment.json", payload)
        self.logger.info(f"Saved → {OUTPUT_DIR}/risk_assessment.json")
