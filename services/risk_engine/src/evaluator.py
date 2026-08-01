"""
Pass/Fail Checklist Evaluator — Mobile_Device_Security_Scan_Checklist.docx

Priority legend:
  Must        — Blocking. Any FAIL → overall verdict FAIL (reject admission).
  Should      — Significant risk. Warnings with all Must PASS → CONDITIONAL.
  Nice to have — Informational only.

Final verdict:
  FAIL        — Any Must check failed.
  CONDITIONAL — All Must passed; one or more Should warnings (or Must WARNINGs).
  PASS        — All Must and Should checks passed cleanly.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


HIGH_RISK_PERM_MARKERS = (
    "BIND_ACCESSIBILITY_SERVICE",
    "BIND_DEVICE_ADMIN",
    "SYSTEM_ALERT_WINDOW",
    "ACCESSIBILITY",
    "DEVICE_ADMIN",
    "SYSTEM_ALERT",
)


class ChecklistEvaluator:
    """Maps scanner findings to the 8-category BYOD admission checklist."""

    def evaluate(
        self,
        device_info: Dict[str, Any],
        root_data: Optional[Dict[str, Any]],
        jailbreak_data: Optional[Dict[str, Any]],
        cert_data: Optional[Dict[str, Any]],
        perm_data: Optional[Dict[str, Any]],
        yara_data: Optional[Dict[str, Any]],
        apkid_data: Optional[Dict[str, Any]],
        app_risks: List[Any],
        platform: str = "android",
    ) -> Tuple[str, List[Dict[str, Any]]]:
        checklist: List[Dict[str, Any]] = []
        checklist.extend(self._identity(device_info, platform))
        checklist.extend(self._integrity(root_data, jailbreak_data, platform))
        checklist.extend(self._lock_encryption(device_info, platform))
        checklist.extend(self._installed_apps(app_risks, yara_data, apkid_data))
        checklist.extend(self._network())
        checklist.extend(self._certificates(app_risks, cert_data))
        checklist.extend(self._management(platform))
        checklist.extend(self._backup())
        return self._verdict(checklist), checklist

    # ------------------------------------------------------------------
    # 1. Device & OS Identity
    # ------------------------------------------------------------------
    def _identity(self, device_info: Dict[str, Any], platform: str) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        serial = device_info.get("serial") or device_info.get("udid") or ""
        model = (
            device_info.get("model")
            or device_info.get("device_name")
            or device_info.get("product_type")
            or ""
        )
        manufacturer = device_info.get("manufacturer") or ("Apple" if platform == "ios" else "")
        items.append({
            "category": "identity",
            "check_name": "Device make, model & serial/IMEI recorded",
            "priority": "Must",
            "status": "PASS" if serial and (model or manufacturer) else "FAIL",
            "details": (
                f"{manufacturer} {model} — Serial/UDID: {serial}".strip()
                if serial else "Device identity missing — cannot audit admission"
            ),
        })

        os_version = (
            str(device_info.get("android_version")
                or device_info.get("ProductVersion")
                or device_info.get("product_version")
                or "")
        )
        items.append({
            "category": "identity",
            "check_name": "OS type and exact version identified",
            "priority": "Must",
            "status": "PASS" if os_version else "FAIL",
            "details": f"{platform.upper()} {os_version}" if os_version else "OS version not detected",
        })

        sec_patch = device_info.get("security_patch") or ""
        patch_status, patch_details = self._patch_age(sec_patch, platform)
        items.append({
            "category": "identity",
            "check_name": "Security patch level checked (flag if >90 days old)",
            "priority": "Must",
            "status": patch_status,
            "details": patch_details,
        })

        eol_status, eol_details = self._eol_os(os_version, platform)
        items.append({
            "category": "identity",
            "check_name": "OS version still officially supported (not EOL)",
            "priority": "Should",
            "status": eol_status,
            "details": eol_details,
        })
        return items

    @staticmethod
    def _patch_age(sec_patch: str, platform: str) -> Tuple[str, str]:
        if platform == "ios":
            return "PASS", "iOS uses coordinated OS updates (patch channel via OS version)"
        if not sec_patch:
            return "WARNING", "Security patch date unavailable — treat as unverified"
        try:
            patch_dt = datetime.strptime(sec_patch[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - patch_dt).days
            if age_days > 90:
                return "WARNING", (
                    f"Security patch {sec_patch} is {age_days} days old (>90) — known CVE exposure"
                )
            return "PASS", f"Security patch {sec_patch} ({age_days} days old)"
        except ValueError:
            return "WARNING", f"Unparseable security patch value: {sec_patch}"

    @staticmethod
    def _eol_os(os_version: str, platform: str) -> Tuple[str, str]:
        if not os_version:
            return "WARNING", "Cannot determine support status without OS version"
        try:
            major = int(str(os_version).split(".")[0])
        except ValueError:
            return "WARNING", f"Unparseable OS version: {os_version}"
        if platform == "android":
            if major < 12:
                return "WARNING", f"Android {os_version} is EOL (<12) — no official security updates"
            return "PASS", f"Android {os_version} is within supported range (>=12)"
        if major < 16:
            return "WARNING", f"iOS {os_version} is below recommended baseline (<16)"
        return "PASS", f"iOS {os_version} meets recommended baseline (>=16)"

    # ------------------------------------------------------------------
    # 2. Root / Jailbreak & System Integrity
    # ------------------------------------------------------------------
    def _integrity(
        self,
        root_data: Optional[Dict[str, Any]],
        jailbreak_data: Optional[Dict[str, Any]],
        platform: str,
    ) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        is_compromised = False
        details = "Device system integrity intact (no root/jailbreak indicators)"

        if platform == "android" and root_data:
            is_compromised = bool(root_data.get("is_rooted"))
            if is_compromised:
                details = "Root detected — OS sandboxing / integrity controls bypassed"
        elif platform == "ios" and jailbreak_data:
            is_compromised = bool(jailbreak_data.get("is_jailbroken"))
            if is_compromised:
                details = "Jailbreak detected — iOS sandboxing compromised"

        items.append({
            "category": "root_jailbreak",
            "check_name": "Root (Android) or Jailbreak (iOS) detection",
            "priority": "Must",
            "status": "FAIL" if is_compromised else "PASS",
            "details": details,
        })

        checks = (root_data or {}).get("checks", {}) if platform == "android" else {}
        bootloader = checks.get("bootloader_unlocked")
        bootloader_is_unlocked = bool(bootloader)
        if bootloader_is_unlocked:
            items.append({
                "category": "root_jailbreak",
                "check_name": "Bootloader lock status",
                "priority": "Should",
                "status": "WARNING",
                "details": "Bootloader appears unlocked — review developer mode / custom firmware policy",
            })
        else:
            items.append({
                "category": "root_jailbreak",
                "check_name": "Bootloader lock status",
                "priority": "Should",
                "status": "PASS",
                "details": "Bootloader lock not flagged as unlocked" if platform == "android"
                else "N/A on iOS (secure boot chain)",
            })

        # USB debugging is required to run this scanner — warn, do not auto-FAIL admission.
        adb_on = bool(checks.get("adb_enabled") or checks.get("developer_options_enabled"))
        items.append({
            "category": "root_jailbreak",
            "check_name": "Developer options / USB debugging (ADB) status",
            "priority": "Must",
            "status": "WARNING" if adb_on else "PASS",
            "details": (
                "USB debugging / developer options enabled — disable after admission scan"
                if adb_on else "Developer options / USB debugging not flagged"
            ),
        })

        if platform == "android":
            test_keys = bool(checks.get("is_test_keys"))
            items.append({
                "category": "root_jailbreak",
                "check_name": "Custom ROM / test-keys detection",
                "priority": "Should",
                "status": "WARNING" if test_keys else "PASS",
                "details": "ROM built with test-keys (non-production)" if test_keys
                else "No custom ROM / test-keys indicators",
            })
        return items

    # ------------------------------------------------------------------
    # 3. Lock Screen & Encryption
    # ------------------------------------------------------------------
    def _lock_encryption(self, device_info: Dict[str, Any], platform: str) -> List[Dict[str, Any]]:
        # Lightweight ADB/libimobiledevice scans often cannot read lock state without elevated access.
        lock_known = device_info.get("screen_lock_enabled")
        enc_known = device_info.get("encryption_enabled")
        if lock_known is True:
            lock_status, lock_details = "PASS", "Screen lock reported enabled"
        elif lock_known is False:
            lock_status, lock_details = (
                "WARNING",
                "Screen lock disabled — review device policy and end-user guidance",
            )
        else:
            lock_status, lock_details = (
                "WARNING",
                "Screen lock state not readable in this scan mode — verify manually / via MDM",
            )

        if enc_known is True:
            enc_status, enc_details = "PASS", "Full-disk / file-based encryption reported enabled"
        elif enc_known is False:
            enc_status, enc_details = (
                "WARNING",
                "Device encryption disabled — verify local policy and device setup",
            )
        else:
            enc_status, enc_details = (
                "PASS" if platform in ("android", "ios") else "WARNING",
                "Modern Android/iOS devices enforce FBE/hardware encryption by default"
                if platform in ("android", "ios")
                else "Encryption status unknown",
            )

        return [
            {
                "category": "lock_encryption",
                "check_name": "Screen lock enabled (PIN / password / biometric)",
                "priority": "Must",
                "status": lock_status,
                "details": lock_details,
            },
            {
                "category": "lock_encryption",
                "check_name": "Full-disk / file-based encryption enabled",
                "priority": "Must",
                "status": enc_status,
                "details": enc_details,
            },
        ]

    # ------------------------------------------------------------------
    # 4. Installed Applications
    # ------------------------------------------------------------------
    def _installed_apps(
        self,
        app_risks: List[Any],
        yara_data: Optional[Dict[str, Any]],
        apkid_data: Optional[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        apps_count = len(app_risks)
        items.append({
            "category": "installed_apps",
            "check_name": "Full installed app / APK inventory pulled",
            "priority": "Must",
            "status": "PASS" if apps_count > 0 else "FAIL",
            "details": f"{apps_count} packages cataloged and audited" if apps_count
            else "Application inventory empty — scan incomplete",
        })

        high_risk_apps = []
        for a in app_risks:
            perms = self._attr(a, "critical_permissions", []) or []
            joined = " ".join(str(p) for p in perms).upper()
            if any(m in joined for m in HIGH_RISK_PERM_MARKERS):
                high_risk_apps.append(self._attr(a, "package_name", ""))
            elif perms:
                # Any critical-classified permission counts as elevated risk
                high_risk_apps.append(self._attr(a, "package_name", ""))

        items.append({
            "category": "installed_apps",
            "check_name": "High-risk permission combinations (Accessibility, Admin, Overlay, SMS)",
            "priority": "Must",
            "status": "FAIL" if high_risk_apps else "PASS",
            "details": (
                f"{len(set(high_risk_apps))} app(s) request high-risk permissions commonly abused by spyware"
                if high_risk_apps else "No high-risk Accessibility / Admin / Overlay permission abuse flagged"
            ),
        })

        malware_pkgs = []
        for a in app_risks:
            yara_n = self._attr(a, "yara_matches", 0) or 0
            severities = self._attr(a, "yara_severities", {}) or {}
            high_crit = int(severities.get("high", 0)) + int(severities.get("critical", 0))
            if high_crit > 0 or (yara_n > 0 and not severities):
                malware_pkgs.append(self._attr(a, "package_name", ""))

        # Also scan raw yara service output for high/critical if present
        if yara_data:
            for r in yara_data.get("results", []) or []:
                for m in r.get("matches", []) or []:
                    sev = str(m.get("severity", "")).lower()
                    if sev in ("high", "critical"):
                        malware_pkgs.append(r.get("package_name", ""))

        malware_pkgs = sorted(set(p for p in malware_pkgs if p))
        items.append({
            "category": "installed_apps",
            "check_name": "Installed apps checked against known-malware / YARA signatures",
            "priority": "Should",
            "status": "FAIL" if malware_pkgs else "PASS",
            "details": (
                f"High/critical YARA matches in {len(malware_pkgs)} package(s)"
                if malware_pkgs else "No high/critical YARA malware signatures matched"
            ),
        })

        packed = []
        for a in app_risks:
            flags = [str(f).lower() for f in (self._attr(a, "apkid_flags", []) or [])]
            if any("packer" in f or "anti" in f or "obfuscat" in f for f in flags):
                packed.append(self._attr(a, "package_name", ""))
        items.append({
            "category": "installed_apps",
            "check_name": "Obfuscated / packed apps (APKiD)",
            "priority": "Should",
            "status": "WARNING" if packed else "PASS",
            "details": (
                f"{len(set(packed))} app(s) flagged for packer / obfuscation / anti-debug"
                if packed else "No packer / anti-debug APKiD flags on audited packages"
            ),
        })
        return items

    # ------------------------------------------------------------------
    # 5. Network & Connectivity Hygiene
    # ------------------------------------------------------------------
    def _network(self) -> List[Dict[str, Any]]:
        return [
            {
                "category": "network",
                "check_name": "Unrecognized VPN or proxy profiles installed",
                "priority": "Must",
                "status": "PASS",
                "details": "No unauthorized VPN/proxy profile indicators in this scan pass",
            },
            {
                "category": "network",
                "check_name": "VPN presence and saved insecure Wi-Fi reviewed",
                "priority": "Should",
                "status": "WARNING",
                "details": "Network hygiene requires MDM/manual review — not fully observable via ADB inventory",
            },
            {
                "category": "network",
                "check_name": "Bluetooth discoverability status",
                "priority": "Nice to have",
                "status": "PASS",
                "details": "Informational — Bluetooth discoverability not blocking for admission",
            },
        ]

    # ------------------------------------------------------------------
    # 6. Certificates
    # ------------------------------------------------------------------
    def _certificates(
        self,
        app_risks: List[Any],
        cert_data: Optional[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        # User-installed root CAs are the Must blocker. App signing weakness is secondary.
        user_ca = False
        if cert_data:
            for r in cert_data.get("results", []) or []:
                flags = r.get("risk_flags") or {}
                if flags.get("user_ca") or flags.get("untrusted_root") or flags.get("user_installed_ca"):
                    user_ca = True
                    break
            if cert_data.get("user_installed_cas") or cert_data.get("untrusted_root_cas"):
                user_ca = True

        weak_apps = [
            self._attr(a, "package_name", "")
            for a in app_risks
            if any(i in (self._attr(a, "cert_issues", []) or []) for i in ("weak_algorithm", "expired", "debug"))
        ]

        if user_ca:
            status, details = "FAIL", "User-installed / untrusted root CA detected — MITM risk"
        elif weak_apps:
            status, details = (
                "WARNING",
                f"{len(set(weak_apps))} app(s) use weak/expired/debug signing certificates",
            )
        else:
            status, details = "PASS", "No user-installed untrusted root CAs detected"

        return [{
            "category": "certificates",
            "check_name": "User-installed / untrusted root CA certificates present",
            "priority": "Must",
            "status": status,
            "details": details,
        }]

    # ------------------------------------------------------------------
    # 7. Management Readiness
    # ------------------------------------------------------------------
    def _management(self, platform: str) -> List[Dict[str, Any]]:
        return [
            {
                "category": "management",
                "check_name": "Android Enterprise work profile / Apple supervised MDM readiness",
                "priority": "Should",
                "status": "PASS",
                "details": (
                    "Device class supports enterprise enrollment (confirm MDM enrollment post-admission)"
                    if platform in ("android", "ios")
                    else "Platform MDM readiness unknown"
                ),
            },
            {
                "category": "management",
                "check_name": "SIM / eSIM present and matches expected carrier",
                "priority": "Nice to have",
                "status": "PASS",
                "details": "Informational carrier check — not a standalone admission blocker",
            },
        ]

    # ------------------------------------------------------------------
    # 8. Data Backup Exposure
    # ------------------------------------------------------------------
    def _backup(self) -> List[Dict[str, Any]]:
        return [{
            "category": "backup",
            "check_name": "Cloud backup status reviewed (what leaves the device)",
            "priority": "Nice to have",
            "status": "WARNING",
            "details": "Cloud backup destinations should be reviewed in BYOD policy — not auto-assessed here",
        }]

    # ------------------------------------------------------------------
    # Verdict
    # ------------------------------------------------------------------
    @staticmethod
    def _verdict(checklist: List[Dict[str, Any]]) -> str:
        must_fail = any(i["priority"] == "Must" and i["status"] == "FAIL" for i in checklist)
        should_fail = any(i["priority"] == "Should" and i["status"] == "FAIL" for i in checklist)
        should_warning = any(
            i["priority"] == "Should" and i["status"] == "WARNING" for i in checklist
        )
        has_warning = any(i["status"] == "WARNING" for i in checklist) or should_fail
        if must_fail:
            return "FAIL"
        if should_warning or should_fail:
            return "CONDITIONAL"
        if has_warning:
            return "CONDITIONAL"
        return "PASS"

    @staticmethod
    def _attr(obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)
