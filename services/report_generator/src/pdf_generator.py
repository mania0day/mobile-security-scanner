"""
Professional PDF Admission & Forensic Analysis Report.
Structured similarly to commercial sandbox reports (branded cover, score gauge,
KPI cards, graphs, findings matrix, CVE exposure, recommendations, certification).
"""
from __future__ import annotations

import os
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas as _canvas
from reportlab.platypus import (
    Flowable,
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

TEAL = colors.HexColor("#0F766E")
TEAL_DARK = colors.HexColor("#134E4A")
INK = colors.HexColor("#0F172A")
MUTED = colors.HexColor("#64748B")
LINE = colors.HexColor("#E2E8F0")
PASS_C = colors.HexColor("#15803D")
WARN_C = colors.HexColor("#B45309")
FAIL_C = colors.HexColor("#B91C1C")
CRIT_C = colors.HexColor("#991B1B")
HIGH_C = colors.HexColor("#C2410C")
MED_C = colors.HexColor("#CA8A04")
LOW_C = colors.HexColor("#15803D")

PASS_TINT = colors.HexColor("#F0FDF4")
WARN_TINT = colors.HexColor("#FFFBEB")
FAIL_TINT = colors.HexColor("#FEF2F2")
PANEL_BG = colors.HexColor("#F8FAFC")

CATEGORY_LABELS = {
    "identity": "Device & OS Identity",
    "root_jailbreak": "Root / Jailbreak & Integrity",
    "lock_encryption": "Lock Screen & Encryption",
    "installed_apps": "Installed Applications",
    "network": "Network & Connectivity",
    "certificates": "Certificates",
    "management": "Management Readiness",
    "backup": "Data Backup Exposure",
}

REMEDIATIONS = {
    "identity": "Update the device to a vendor-supported OS build and verify the Android security patch level.",
    "root_jailbreak": "Remove root / jailbreak, restore stock firmware, and re-run the scan before admission.",
    "lock_encryption": "Enroll a strong screen lock (PIN/biometric) and enable full-disk or file-based encryption.",
    "installed_apps": "Uninstall or sandbox the flagged applications and enforce an application allowlist via MDM.",
    "network": "Force TLS 1.2+, disable cleartext traffic, and review VPN posture and open ports.",
    "certificates": "Revoke or replace the flagged certificate and enforce certificate pinning for corporate services.",
    "management": "Enroll the device in MDM / UEM and enforce compliance, conditional-access and remote-wipe policies.",
    "backup": "Disable insecure cloud backup and restrict USB debugging / ADB sessions to authorized hosts.",
}


class NumberedCanvas(_canvas.Canvas):
    """Canvas that draws a branded header/footer on every page except the cover,
    including a 'Page X of Y' footer."""

    report_id = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states: List[Dict[str, Any]] = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_frame(total)
            super().showPage()
        super().save()

    def _draw_frame(self, total: int):
        page = self._pageNumber
        if page == 1:
            return
        w, h = self._pagesize
        rid = self.report_id or ""
        self.saveState()
        # Top header band
        self.setFillColor(INK)
        self.rect(0, h - 30, w, 30, stroke=0, fill=1)
        self.setFillColor(colors.white)
        self.setFont("Helvetica-Bold", 7.5)
        self.drawString(36, h - 20, "MOBILE SECURITY SCANNER")
        self.setFont("Helvetica", 7)
        self.setFillColor(colors.HexColor("#94A3B8"))
        self.drawString(36, h - 12, "BYOD Admission & Forensic Analysis")
        self.setFillColor(colors.white)
        self.drawRightString(w - 36, h - 20, f"Report {rid}")
        self.setStrokeColor(TEAL)
        self.setLineWidth(2)
        self.line(36, h - 30, w - 36, h - 30)
        # Footer band
        self.setStrokeColor(LINE)
        self.setLineWidth(0.5)
        self.line(36, 36, w - 36, 36)
        self.setFont("Helvetica", 6.5)
        self.setFillColor(MUTED)
        self.drawString(36, 24, "CONFIDENTIAL — For internal BYOD admission auditing")
        self.drawCentredString(w / 2, 24, f"Page {page} of {total}")
        self.drawRightString(w - 36, 24, rid)
        self.restoreState()


class ScoreGauge(Flowable):
    """Circular risk score gauge (centred when given the full frame width)."""

    def __init__(self, score: int, width: float = 520, height: float = 150):
        super().__init__()
        self.score = max(0, min(100, int(score or 0)))
        self._w = width
        self._h = height

    def wrap(self, availWidth, availHeight):
        self.width = min(self._w, availWidth)
        self.height = self._h
        return self.width, self.height

    def draw(self):
        c = self.canv
        cx, cy = self.width / 2, self.height / 2
        r = min(self.width, self.height) / 2 - 10
        color = FAIL_C if self.score >= 75 else WARN_C if self.score >= 50 else MED_C if self.score >= 25 else PASS_C

        c.setStrokeColor(LINE)
        c.setLineWidth(14)
        c.circle(cx, cy, r, stroke=1, fill=0)

        # ReportLab's own bezierArc() divides by sin(halfAng) internally and
        # raises ZeroDivisionError for an arc extent of exactly 0 or a full
        # +/-360 — both reachable here at score 0 (clean device) or 100.
        extent = -360 * (self.score / 100.0)
        if extent != 0:
            if abs(extent) >= 360:
                extent = -359.99 if extent < 0 else 359.99
            c.setStrokeColor(color)
            c.setLineWidth(14)
            c.setLineCap(1)
            c.arc(cx - r, cy - r, cx + r, cy + r, 90, extent)

        c.setFillColor(INK)
        c.setFont("Helvetica-Bold", 26)
        c.drawCentredString(cx, cy + 2, str(self.score))
        c.setFillColor(MUTED)
        c.setFont("Helvetica-Bold", 8)
        c.drawCentredString(cx, cy - 20, "RISK SCORE / 100")


class HBarChart(Flowable):
    """Horizontal bar chart for category health or top apps."""

    def __init__(self, rows: List[Tuple[str, float, Any]], width: float = 480, row_h: float = 18):
        super().__init__()
        self.rows = rows[:10]
        self._chart_width = width
        self.row_h = row_h
        self.label_w = 130
        self._h = max(40, len(self.rows) * (row_h + 6) + 8)
        self._w = width

    def wrap(self, availWidth, availHeight):
        self.width = min(self._w, availWidth)
        self.height = self._h
        return self.width, self.height

    def draw(self):
        c = self.canv
        y = self.height - self.row_h
        bar_max = max(40, self.width - self.label_w - 40)
        for label, value, color in self.rows:
            c.setFillColor(MUTED)
            c.setFont("Helvetica", 7)
            c.drawString(0, y + 4, (label or "")[:28])
            c.setFillColor(LINE)
            c.roundRect(self.label_w, y + 2, bar_max, 10, 3, stroke=0, fill=1)
            w = max(2, bar_max * (max(0, min(100, value)) / 100.0))
            c.setFillColor(color)
            c.roundRect(self.label_w, y + 2, w, 10, 3, stroke=0, fill=1)
            c.setFillColor(INK)
            c.setFont("Helvetica-Bold", 7)
            c.drawRightString(self.width - 2, y + 4, f"{int(value)}")
            y -= self.row_h + 6


def _styles():
    base = getSampleStyleSheet()
    return {
        "brand": ParagraphStyle(
            "Brand", parent=base["Heading1"], fontSize=28, leading=32,
            textColor=TEAL_DARK, fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=2,
        ),
        "cover_title": ParagraphStyle(
            "CoverTitle", parent=base["Heading1"], fontSize=22, leading=26,
            textColor=INK, fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=8,
        ),
        "cover_sub": ParagraphStyle(
            "CoverSub", parent=base["Normal"], fontSize=11, leading=15,
            textColor=MUTED, alignment=TA_CENTER, spaceAfter=4,
        ),
        "cover_meta": ParagraphStyle(
            "CoverMeta", parent=base["Normal"], fontSize=9, leading=14,
            textColor=MUTED, alignment=TA_CENTER, spaceAfter=2,
        ),
        "h1": ParagraphStyle(
            "H1", parent=base["Heading1"], fontSize=16, leading=20,
            textColor=INK, fontName="Helvetica-Bold", spaceBefore=4, spaceAfter=8,
        ),
        "h2": ParagraphStyle(
            "H2", parent=base["Heading2"], fontSize=12, leading=15,
            textColor=INK, fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "Body", parent=base["Normal"], fontSize=9, leading=13, textColor=INK,
        ),
        "muted": ParagraphStyle(
            "Muted", parent=base["Normal"], fontSize=8, leading=11, textColor=MUTED,
        ),
        "small": ParagraphStyle(
            "Small", parent=base["Normal"], fontSize=7.5, leading=10, textColor=MUTED,
        ),
        "cell": ParagraphStyle(
            "Cell", parent=base["Normal"], fontSize=8, leading=11, textColor=INK,
        ),
        "cell_b": ParagraphStyle(
            "CellB", parent=base["Normal"], fontSize=8, leading=11, textColor=INK, fontName="Helvetica-Bold",
        ),
    }


def _verdict_colors(verdict: str):
    v = (verdict or "PASS").upper()
    if v == "FAIL":
        return FAIL_TINT, FAIL_C, "REJECTED — DO NOT ADMIT"
    if v == "CONDITIONAL":
        return WARN_TINT, WARN_C, "CONDITIONAL ADMISSION"
    return PASS_TINT, PASS_C, "APPROVED FOR ADMISSION"


def _cat_label(key: str) -> str:
    return CATEGORY_LABELS.get(key, (key or "").replace("_", " ").title())


def _status_color(status: str):
    s = (status or "").upper()
    if s == "FAIL":
        return FAIL_C
    if s == "WARNING":
        return WARN_C
    return PASS_C


def _level_color(level: str):
    l = (level or "").upper()
    return {"CRITICAL": CRIT_C, "HIGH": HIGH_C, "MEDIUM": MED_C, "LOW": LOW_C}.get(l, MUTED)


def _severity_color(tier: str):
    t = (tier or "").lower()
    return {
        "safe": PASS_C,
        "low risk": MED_C,
        "vulnerable": WARN_C,
        "compromisable": HIGH_C,
        "critical": FAIL_C,
    }.get(t, MUTED)


def _checklist(data: dict) -> List[dict]:
    return data.get("checklist_evaluations") or data.get("checklist") or []


def _apps(data: dict) -> List[dict]:
    return data.get("app_risks") or data.get("app_findings") or data.get("top_risky_apps") or []


def _device(data: dict) -> dict:
    return data.get("device") or {}


def _cves(data: dict) -> Tuple[List[dict], dict]:
    raw = data.get("cve_findings")
    if raw is None:
        return [], {}
    if isinstance(raw, dict):
        return raw.get("cves") or [], raw
    return list(raw), {}


def _executive_summary(data: dict, checklist: List[dict], apps: List[dict]) -> str:
    verdict = (data.get("verdict") or "PASS").upper()
    score = data.get("overall_score", 0)
    fails = [c for c in checklist if c.get("status") == "FAIL"]
    warns = [c for c in checklist if c.get("status") == "WARNING"]
    must_fails = [f for f in fails if f.get("priority") == "Must"]
    critical_apps = sum(1 for a in apps if (a.get("risk_level") or "").upper() == "CRITICAL")
    device = _device(data)
    name = f"{device.get('manufacturer', '')} {device.get('model', '')}".strip() or data.get("device_serial", "Unknown device")

    if verdict == "FAIL":
        blockers = "; ".join(c.get("check_name", "") for c in must_fails[:3]) or "policy violations"
        return (
            f"<b>{name}</b> is <b>REJECTED</b> for BYOD admission (risk score {score}/100). "
            f"{len(must_fails)} Must-priority check(s) failed — primary blockers: {blockers}. "
            f"Inventory covered {len(apps)} packages ({critical_apps} critical). "
            f"Remediate blockers and re-scan before network admission."
        )
    if verdict == "CONDITIONAL":
        return (
            f"<b>{name}</b> may be admitted <b>conditionally</b> (risk score {score}/100). "
            f"All Must checks passed; {len(warns)} warning(s) require follow-up / MDM policy. "
            f"{len(apps)} packages analyzed ({critical_apps} critical)."
        )
    return (
        f"<b>{name}</b> is <b>APPROVED</b> for admission (risk score {score}/100). "
        f"All Must and Should checks passed. {len(apps)} packages audited with no blocking findings."
    )


def _kpi_table(score: int, passed: int, must_fails: int, critical: int, S) -> Table:
    def cell(big: str, label: str, tint, color):
        inner = [
            [Paragraph(f"<font color='{color.hexval()}'><b>{big}</b></font>",
                       ParagraphStyle("K", fontSize=16, fontName="Helvetica-Bold", leading=18, alignment=TA_CENTER))],
            [Paragraph(label.upper(), ParagraphStyle("KL", fontSize=6.5, leading=8, textColor=MUTED, alignment=TA_CENTER))],
        ]
        t = Table(inner, colWidths=[115])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), tint),
            ("BOX", (0, 0), (-1, -1), 0.5, LINE),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        return t

    row = [
        cell(str(score), "Risk score", PANEL_BG, INK),
        cell(str(passed), "Checks passed", PASS_TINT, PASS_C),
        cell(str(must_fails), "Must failures", FAIL_TINT, FAIL_C),
        cell(str(critical), "Critical apps", WARN_TINT, WARN_C),
    ]
    kpi = Table([row], colWidths=[115, 115, 115, 115])
    kpi.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    return kpi


def _recommendations(checklist: List[dict]) -> List[Tuple[str, str, str]]:
    out: List[Tuple[str, str, str]] = []
    for c in checklist:
        st = c.get("status")
        if st == "FAIL":
            out.append(("MUST", c.get("check_name", ""), REMEDIATIONS.get(c.get("category", ""),
                                                                           "Review and remediate before admission.")))
        elif st == "WARNING":
            out.append(("SHOULD", c.get("check_name", ""), REMEDIATIONS.get(c.get("category", ""),
                                                                           "Review and monitor.")))
    return out[:12]


def generate_pdf_report(data: dict, output_filepath: str) -> str:
    os.makedirs(os.path.dirname(output_filepath) or ".", exist_ok=True)
    doc = SimpleDocTemplate(
        output_filepath,
        pagesize=letter,
        rightMargin=42,
        leftMargin=42,
        topMargin=58,
        bottomMargin=52,
    )
    S = _styles()
    story: List[Any] = []

    verdict = (data.get("verdict") or "PASS").upper()
    score = int(data.get("overall_score") or 0)
    level = data.get("overall_level") or data.get("device_risk_level") or "—"
    device = _device(data)
    checklist = _checklist(data)
    apps = _apps(data)
    cves, cve_meta = _cves(data)
    serial = data.get("device_serial") or device.get("serial") or "—"
    scan_id = data.get("scan_id") or serial
    mode = (data.get("scan_mode") or "minimal").upper()
    platform = (device.get("platform") or data.get("platform") or "android").upper()
    ts = str(data.get("scan_timestamp") or "").replace("T", " ")[:19]
    banner_bg, banner_fg, banner_label = _verdict_colors(verdict)
    safe = bool(data.get("safe_mode"))

    def mask(v):
        if safe:
            return "REDACTED"
        return str(v or "—")

    if safe:
        # The device serial is itself an identifying field — redact it, and make
        # sure scan_id (printed on every page header/footer via NumberedCanvas)
        # never silently falls back to the raw serial when it wasn't explicitly
        # set. scan_id should already come from the DB scan id (not the device
        # serial) — this is just a defensive guard against that fallback.
        if scan_id == serial:
            scan_id = data.get("scan_id") or "REDACTED"
        serial = "REDACTED"

    # ─────────────────────────── COVER ───────────────────────────
    story.append(Spacer(1, 18))
    story.append(Paragraph("MOBILE SECURITY SCANNER", S["brand"]))
    story.append(Paragraph("BYOD Admission &amp; Forensic Analysis Report", S["cover_title"]))
    story.append(Paragraph("Automated compliance audit of the device against the Mobile Device Security Scan Checklist", S["cover_sub"]))
    story.append(Spacer(1, 16))
    story.append(Paragraph(f"Report ID&nbsp;&nbsp;<font face='Courier' size='9'><b>{scan_id}</b></font>", S["cover_meta"]))
    story.append(Paragraph(
        f"Mode <b>{mode}</b> &nbsp;·&nbsp; Platform <b>{platform}</b> &nbsp;·&nbsp; Generated {ts}",
        S["cover_meta"],
    ))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=2, color=TEAL, spaceAfter=4))
    story.append(Spacer(1, 6))

    # Score gauge (full width => centred)
    story.append(ScoreGauge(score, 520, 160))
    story.append(Spacer(1, 10))

    # Verdict banner
    verdict_box = Table(
        [[
            Paragraph(f"<font color='{banner_fg.hexval()}'><b>{banner_label}</b></font>",
                      ParagraphStyle("VB", fontSize=15, fontName="Helvetica-Bold", leading=18, alignment=TA_CENTER)),
        ]],
        colWidths=[520],
    )
    verdict_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), banner_bg),
        ("BOX", (0, 0), (-1, -1), 1.4, banner_fg),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(verdict_box)
    story.append(Spacer(1, 8))
    severity_tier = data.get("severity_tier") or "Safe"
    severity_line = (
        f"Severity <font color='{_severity_color(severity_tier).hexval()}'><b>{severity_tier.upper()}</b></font> &nbsp;·&nbsp; "
        if mode != "QUICK" else ""
    )
    story.append(Paragraph(
        f"Verdict <b>{verdict}</b> &nbsp;·&nbsp; {severity_line}Risk level <b>{level}</b> &nbsp;·&nbsp; "
        f"<b>{device.get('manufacturer', '')} {device.get('model', '')}</b>".strip(),
        S["cover_meta"],
    ))
    story.append(Paragraph(f"<font face='Courier' size='8'>{serial}</font>", S["cover_meta"]))
    story.append(Spacer(1, 14))

    # Tags strip
    tags = [verdict, mode]
    if mode != "QUICK":
        tags.append(severity_tier.upper())
    if device.get("android_version") or device.get("os_version"):
        tags.append(f"OS {device.get('android_version') or device.get('os_version')}")
    fail_n = sum(1 for c in checklist if c.get("status") == "FAIL")
    warn_n = sum(1 for c in checklist if c.get("status") == "WARNING")
    if fail_n:
        tags.append(f"{fail_n} FAIL")
    if warn_n:
        tags.append(f"{warn_n} WARN")
    crit = sum(1 for a in apps if (a.get("risk_level") or "").upper() == "CRITICAL")
    if crit:
        tags.append(f"{crit} CRITICAL APPS")
    if cves:
        tags.append(f"{len(cves)} CVES")
    tag_cells = [[Paragraph(f"<b>{t}</b>", ParagraphStyle("Tag", fontSize=7, textColor=TEAL, alignment=TA_CENTER)) for t in tags]]
    tag_table = Table(tag_cells, colWidths=[min(90, 520 / max(len(tags), 1))] * len(tags))
    tag_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0FDFA")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#99F6E4")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#99F6E4")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(tag_table)
    story.append(PageBreak())

    # ─────────────────────── 1. EXEC SUMMARY ───────────────────────
    passed = sum(1 for c in checklist if c.get("status") == "PASS")
    must_fails = sum(1 for c in checklist if c.get("priority") == "Must" and c.get("status") == "FAIL")
    story.append(Paragraph("1. Executive Summary", S["h1"]))
    story.append(Paragraph(_executive_summary(data, checklist, apps), S["body"]))
    story.append(Spacer(1, 10))
    story.append(_kpi_table(score, passed, must_fails, crit, S))
    story.append(Spacer(1, 10))

    # ─────────────────────── 2. DEVICE PROFILE ───────────────────────
    story.append(Paragraph("2. Device Profile", S["h1"]))
    device_risk = data.get("device_risk") or {}
    summary = data.get("summary") or {}
    lock = device.get("screen_lock_enabled")
    enc = device.get("encryption_enabled")

    def yn(v):
        if v is True:
            return "YES"
        if v is False:
            return "NO"
        return "—"

    meta_rows = [
        ["Manufacturer", device.get("manufacturer") or "—", "Model", device.get("model") or "—"],
        ["Serial / UDID", serial, "Platform", platform],
        ["OS Version", str(device.get("android_version") or device.get("os_version") or "—"),
         "SDK", str(device.get("sdk") or device.get("sdk_version") or "—")],
        ["Security Patch", str(device.get("security_patch") or "—"),
         "Build ID", str(device.get("build_id") or "—")],
        ["Hardware", str(device.get("hardware") or "—"),
         "Bootloader", str(device.get("bootloader") or "—")],
        ["Radio", str(device.get("radio_version") or "—"),
         "Rooted", "YES" if device_risk.get("is_rooted") else "NO"],
        ["OEM Unlock Allowed", yn(device_risk.get("oem_unlock_allowed")),
         "Bootloader Unlocked", "YES" if device_risk.get("bootloader_unlocked") else "NO"],
        ["IMEI", mask(device.get("imei")), "IMEI (SIM 2)", mask(device.get("imei_slot2"))],
        ["MEID", mask(device.get("meid")), "Phone", mask(device.get("phone_number"))],
        ["SIM Operator", str(device.get("sim_operator") or "—"),
         "SIM Serial", mask(device.get("sim_serial"))],
        ["Screen Lock", yn(lock), "Encryption", yn(enc)],
        ["Apps Analyzed", str(summary.get("total_apps_analyzed") or len(apps)),
         "Critical / High", f"{summary.get('critical_apps', 0)} / {summary.get('high_apps', 0)}"],
    ]
    meta_data = []
    for r in meta_rows:
        meta_data.append([
            Paragraph(f"<b>{r[0]}</b>", S["small"]),
            Paragraph(str(r[1]), S["cell"]),
            Paragraph(f"<b>{r[2]}</b>", S["small"]),
            Paragraph(str(r[3]), S["cell"]),
        ])
    meta_table = Table(meta_data, colWidths=[100, 160, 100, 160])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), PANEL_BG),
        ("BACKGROUND", (2, 0), (2, -1), PANEL_BG),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(meta_table)

    if lock is None:
        lock_evidence = device.get("screen_lock_evidence") or []
        if lock_evidence:
            story.append(Spacer(1, 4))
            story.append(Paragraph(
                "Screen lock signals disagreed — treated as Unknown rather than guessing. Evidence: "
                + "; ".join(str(e) for e in lock_evidence[:3]),
                S["small"],
            ))

    # ─────────────────────── 3. RISK ANALYTICS ───────────────────────
    story.append(Paragraph("3. Risk Analytics", S["h1"]))

    level_counts = Counter((a.get("risk_level") or "LOW").upper() for a in apps)
    dist_rows = [["Level", "Count", "Share"]]
    total_apps = max(len(apps), 1)
    for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        n = level_counts.get(lvl, 0)
        pct = f"{(n / total_apps) * 100:.0f}%"
        dist_rows.append([
            Paragraph(f"<font color='{_level_color(lvl).hexval()}'><b>{lvl}</b></font>", S["cell"]),
            Paragraph(str(n), S["cell"]),
            Paragraph(pct, S["cell"]),
        ])
    dist_table = Table(dist_rows, colWidths=[120, 80, 80])
    dist_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PANEL_BG),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))

    cat_map: Dict[str, Dict[str, int]] = {}
    for c in checklist:
        key = c.get("category") or "other"
        row = cat_map.setdefault(key, {"pass": 0, "warn": 0, "fail": 0})
        st = c.get("status")
        if st == "FAIL":
            row["fail"] += 1
        elif st == "WARNING":
            row["warn"] += 1
        else:
            row["pass"] += 1

    bar_rows = []
    for key, v in cat_map.items():
        total = v["pass"] + v["warn"] + v["fail"] or 1
        health = round((v["pass"] * 100 + v["warn"] * 40) / total)
        color = FAIL_C if health < 50 else WARN_C if health < 80 else PASS_C
        bar_rows.append((_cat_label(key)[:26], float(health), color))

    story.append(Paragraph("Application severity mix", S["h2"]))
    story.append(dist_table)
    story.append(Spacer(1, 8))
    story.append(Paragraph("Category health (0–100)", S["h2"]))
    if bar_rows:
        story.append(HBarChart(bar_rows, width=500, row_h=16))
    story.append(Spacer(1, 6))

    risky = sorted([a for a in apps if (a.get("risk_score") or 0) > 0], key=lambda x: x.get("risk_score", 0), reverse=True)
    if risky:
        story.append(Paragraph("Top risk packages", S["h2"]))
        top_bars = []
        for a in risky[:8]:
            pkg = a.get("package_name") or ""
            short = ".".join(pkg.split(".")[-2:]) if "." in pkg else pkg
            top_bars.append((short[:28], float(a.get("risk_score") or 0), _level_color(a.get("risk_level", "LOW"))))
        story.append(HBarChart(top_bars, width=500, row_h=16))

    # ─────────────────────── 4. CHECKLIST MATRIX ───────────────────────
    story.append(PageBreak())
    story.append(Paragraph("4. Admission Checklist Matrix", S["h1"]))
    story.append(Paragraph(
        "Mapped to the Mobile Device Security Scan Checklist (Must / Should / Nice to have).",
        S["muted"],
    ))
    story.append(Spacer(1, 6))

    chk_data = [[
        Paragraph("<b>Category</b>", S["cell"]),
        Paragraph("<b>Check</b>", S["cell"]),
        Paragraph("<b>Priority</b>", S["cell"]),
        Paragraph("<b>Status</b>", S["cell"]),
    ]]
    for chk in checklist:
        st = chk.get("status", "PASS")
        chk_data.append([
            Paragraph(_cat_label(chk.get("category", "")), S["small"]),
            Paragraph(
                f"<b>{chk.get('check_name', '')}</b><br/><font color='#64748B'>{chk.get('details', '')}</font>",
                S["cell"],
            ),
            Paragraph(chk.get("priority", "Should"), S["cell"]),
            Paragraph(
                f"<font color='{_status_color(st).hexval()}'><b>{st}</b></font>",
                S["cell"],
            ),
        ])
    chk_table = Table(chk_data, colWidths=[100, 280, 60, 60])
    chk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PANEL_BG),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
    ]))
    story.append(chk_table)

    # ─────────────────────── 5. FINDINGS ───────────────────────
    story.append(Paragraph("5. Structured Findings", S["h1"]))
    findings = []
    for c in checklist:
        if c.get("status") in ("FAIL", "WARNING"):
            findings.append({
                "sev": "CRITICAL" if c.get("status") == "FAIL" else "MEDIUM",
                "title": c.get("check_name", ""),
                "cat": _cat_label(c.get("category", "")),
                "detail": c.get("details", ""),
            })
    for a in risky[:12]:
        if (a.get("risk_level") or "").upper() in ("CRITICAL", "HIGH"):
            findings.append({
                "sev": a.get("risk_level", "HIGH"),
                "title": a.get("package_name", ""),
                "cat": "Application",
                "detail": ", ".join((a.get("risk_factors") or [])[:3]) or f"Score {a.get('risk_score')}",
            })

    if findings:
        f_data = [[
            Paragraph("<b>Severity</b>", S["cell"]),
            Paragraph("<b>Finding</b>", S["cell"]),
            Paragraph("<b>Category</b>", S["cell"]),
            Paragraph("<b>Evidence</b>", S["cell"]),
        ]]
        for f in findings[:25]:
            f_data.append([
                Paragraph(f"<font color='{_level_color(f['sev']).hexval()}'><b>{f['sev']}</b></font>", S["cell"]),
                Paragraph(f["title"], S["cell"]),
                Paragraph(f["cat"], S["small"]),
                Paragraph(f["detail"], S["small"]),
            ])
        f_table = Table(f_data, colWidths=[70, 170, 90, 190])
        f_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PANEL_BG),
            ("GRID", (0, 0), (-1, -1), 0.4, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(f_table)
    else:
        story.append(Paragraph("No open findings — clean admission profile.", S["body"]))

    # ─────────────────────── 6. CVE EXPOSURE ───────────────────────
    story.append(Paragraph("6. CVE Exposure", S["h1"]))
    if cve_meta.get("error"):
        story.append(Paragraph(f"Vulnerability lookup could not be completed: {cve_meta['error']}", S["body"]))
    elif not cves:
        story.append(Paragraph("No known CVEs beyond the device security patch level were identified.", S["body"]))
    else:
        eol_note = ""
        if cve_meta.get("os_eol"):
            eol_note = (f"<br/><font color='#B91C1C'><b>OS end-of-life:</b> {cve_meta.get('os_eol_details', '')}</font>")
        story.append(Paragraph(
            f"<b>{cve_meta.get('total_unpatched', len(cves))}</b> unpatched CVE(s) found for patch "
            f"<b>{cve_meta.get('security_patch') or device.get('security_patch') or '—'}</b> "
            f"({cve_meta.get('critical_count', 0)} critical, {cve_meta.get('high_count', 0)} high). "
            f"Overall vulnerability level: <b>{cve_meta.get('overall_level', '—')}</b>.{eol_note}",
            S["body"],
        ))
        story.append(Spacer(1, 6))
        c_data = [[
            Paragraph("<b>CVE</b>", S["cell"]),
            Paragraph("<b>Severity</b>", S["cell"]),
            Paragraph("<b>CVSS</b>", S["cell"]),
            Paragraph("<b>Component / Title</b>", S["cell"]),
            Paragraph("<b>Bulletin</b>", S["cell"]),
        ]]
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for cv in sorted(cves[:30], key=lambda x: (order.get((x.get("severity") or "LOW").upper(), 9),
                                                   -float(x.get("cvss") or 0))):
            c_data.append([
                Paragraph(f"<font face='Courier' size='7'>{cv.get('id', '')}</font>", S["cell"]),
                Paragraph(f"<font color='{_level_color(cv.get('severity')).hexval()}'><b>{cv.get('severity', '')}</b></font>", S["cell"]),
                Paragraph(str(cv.get("cvss", "")), S["cell"]),
                Paragraph(cv.get("title", ""), S["small"]),
                Paragraph(str(cv.get("bulletin", ""))[:10], S["small"]),
            ])
        c_table = Table(c_data, colWidths=[90, 60, 40, 230, 100])
        c_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PANEL_BG),
            ("GRID", (0, 0), (-1, -1), 0.4, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(c_table)

    # ─────────────────────── 7. APP INVENTORY ───────────────────────
    story.append(Paragraph("7. High-Risk Application Inventory", S["h1"]))
    if risky:
        a_data = [[
            Paragraph("<b>Package</b>", S["cell"]),
            Paragraph("<b>Score</b>", S["cell"]),
            Paragraph("<b>Level</b>", S["cell"]),
            Paragraph("<b>Risk Factors</b>", S["cell"]),
        ]]
        for a in risky[:15]:
            factors = ", ".join((a.get("risk_factors") or [])[:4]) or "—"
            a_data.append([
                Paragraph(f"<font face='Courier' size='7'>{a.get('package_name', '')}</font>", S["cell"]),
                Paragraph(str(a.get("risk_score", 0)), S["cell_b"]),
                Paragraph(
                    f"<font color='{_level_color(a.get('risk_level')).hexval()}'><b>{a.get('risk_level', 'LOW')}</b></font>",
                    S["cell"],
                ),
                Paragraph(factors, S["small"]),
            ])
        a_table = Table(a_data, colWidths=[180, 45, 60, 235])
        a_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PANEL_BG),
            ("GRID", (0, 0), (-1, -1), 0.4, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(a_table)
    else:
        story.append(Paragraph("No elevated-risk applications detected.", S["body"]))

    # ─────────────────────── 8. RECOMMENDATIONS ───────────────────────
    story.append(Paragraph("8. Recommendations &amp; Remediation", S["h1"]))
    recs = _recommendations(checklist)
    if recs:
        rec_rows = []
        for kind, name, action in recs:
            color = FAIL_C if kind == "MUST" else WARN_C
            rec_rows.append([
                Paragraph(f"<font color='{color.hexval()}'><b>{kind}</b></font>", S["cell"]),
                Paragraph(f"<b>{name}</b><br/><font color='#64748B'>{action}</font>", S["cell"]),
            ])
        rec_table = Table(rec_rows, colWidths=[60, 460])
        rec_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 0), (-1, -1), colors.white),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ]))
        story.append(rec_table)
    else:
        story.append(Paragraph("No remediation actions required at this time.", S["body"]))

    # ─────────────────────── 9. CERTIFICATION ───────────────────────
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=1, color=LINE, spaceAfter=8))
    story.append(Paragraph("9. Certification &amp; Attestation", S["h1"]))
    cert = Table([
        [Paragraph(
            f"This report certifies that the device <b>{device.get('manufacturer', '')} {device.get('model', '')}</b> "
            f"(serial <font face='Courier' size='8'>{serial}</font>) was assessed on <b>{ts}</b> using the "
            f"Mobile Security Scanner platform. The admission verdict (<b>{verdict}</b>, risk score <b>{score}/100</b>) "
            f"was derived automatically from the 8-category Mobile Device Security Scan Checklist. "
            f"Re-scan after remediation is recommended.",
            S["body"],
        )],
        [Paragraph(
            f"Verdict logic: <b>FAIL</b> = any Must check failed; <b>CONDITIONAL</b> = Must passed with Should "
            f"warnings; <b>PASS</b> = Must and Should clean.",
            S["small"],
        )],
    ], colWidths=[520])
    cert.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(cert)
    story.append(Spacer(1, 14))

    # Attestation signature block
    sig = Table([[
        Paragraph("________________________<br/><b>Analyst</b>", ParagraphStyle("Sg", fontSize=8, leading=11, alignment=TA_CENTER)),
        Paragraph("________________________<br/><b>Date</b>", ParagraphStyle("Sg", fontSize=8, leading=11, alignment=TA_CENTER)),
        Paragraph("________________________<br/><b>Approving Authority</b>", ParagraphStyle("Sg", fontSize=8, leading=11, alignment=TA_CENTER)),
    ]], colWidths=[173, 173, 174])
    sig.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
        ("TOPPADDING", (0, 0), (-1, -1), 30),
    ]))
    story.append(sig)
    story.append(Spacer(1, 14))

    # Methodology appendix
    story.append(Paragraph("Appendix — Methodology &amp; Tooling", S["h2"]))
    ran = data.get("services_ran") or []
    skipped = data.get("services_skipped") or []
    if ran or skipped:
        meth = f"Analysis services executed: <b>{', '.join(ran) or '—'}</b>."
        if skipped:
            meth += f" Skipped: {', '.join(skipped)}."
        story.append(Paragraph(meth, S["small"]))
    else:
        story.append(Paragraph(
            "Pipeline stages: device collection → static analysis (APKiD, androguard, certificates, permissions) → "
            "integrity (root, YARA) → vulnerability (CVE) → aggregation → report.",
            S["small"],
        ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Confidential — For internal BYOD admission &amp; compliance auditing use only.",
        S["muted"],
    ))

    def _canvas_factory(report_id: str):
        def _inner(*a, **k):
            c = NumberedCanvas(*a, **k)
            c.report_id = report_id
            return c
        return _inner

    doc.build(story, canvasmaker=_canvas_factory(scan_id))
    return output_filepath


def generate_one_pager_report(data: dict, output_filepath: str) -> str:
    """Compact single-page executive summary PDF (no page breaks, minimal sections)."""
    from reportlab.lib.pagesizes import letter

    os.makedirs(os.path.dirname(output_filepath) or ".", exist_ok=True)
    doc = SimpleDocTemplate(
        output_filepath,
        pagesize=letter,
        rightMargin=46,
        leftMargin=46,
        topMargin=48,
        bottomMargin=46,
        title="Mobile Security Scanner — One-Page Summary",
        author="Mobile Security Scanner",
    )
    S = _styles()
    story: List[Any] = []

    verdict = (data.get("verdict") or "PASS").upper()
    score = int(data.get("overall_score") or 0)
    level = data.get("overall_level") or data.get("device_risk_level") or "—"
    device = _device(data)
    checklist = _checklist(data)
    apps = _apps(data)
    cves, cve_meta = _cves(data)
    serial = data.get("device_serial") or device.get("serial") or "—"
    scan_id = data.get("scan_id") or serial
    mode = (data.get("scan_mode") or "minimal").upper()
    ts = str(data.get("scan_timestamp") or "").replace("T", " ")[:16]
    banner_bg, banner_fg, banner_label = _verdict_colors(verdict)
    safe = bool(data.get("safe_mode"))
    name = f"{device.get('manufacturer', '')} {device.get('model', '')}".strip() or "Android device"
    passed = sum(1 for c in checklist if c.get("status") == "PASS")
    must_fails = sum(1 for c in checklist if c.get("priority") == "Must" and c.get("status") == "FAIL")
    warn_n = sum(1 for c in checklist if c.get("status") == "WARNING")
    crit_apps = sum(1 for a in apps if (a.get("risk_level") or "").upper() == "CRITICAL")

    def mask(v):
        if safe:
            return "REDACTED"
        return str(v or "—")

    if safe:
        if scan_id == serial:
            scan_id = data.get("scan_id") or "REDACTED"
        serial = "REDACTED"

    # ── Header band ──
    story.append(Spacer(1, 2))
    header = Table([[Paragraph("MOBILE SECURITY SCANNER", ParagraphStyle(
        "HB", fontSize=15, fontName="Helvetica-Bold", textColor=colors.white, leading=18))],
        [Paragraph("BYOD Admission Summary", ParagraphStyle(
            "HS", fontSize=9, textColor=colors.HexColor("#99F6E4"), leading=11))]],
        colWidths=[528])
    header.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), TEAL_DARK),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, 0), 10),
        ("TOPPADDING", (0, 1), (-1, 1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 2),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 10),
    ]))
    story.append(header)
    story.append(HRFlowable(width="100%", thickness=2, color=TEAL, spaceAfter=10))

    # ── Score gauge + KPIs ── (mirrors the Full report's cover gauge, sized down for one page;
    # width matches the frame so the circle still centers on the page like the cover gauge does)
    story.append(ScoreGauge(score, 528, 110))
    story.append(Spacer(1, 4))
    story.append(_kpi_table(score, passed, must_fails, crit_apps, S))
    story.append(Spacer(1, 8))
    vb = Table([[
        Paragraph(f"<font color='{banner_fg.hexval()}'><b>{banner_label}</b></font>",
                  ParagraphStyle("VB1", fontSize=13, fontName="Helvetica-Bold", leading=16, alignment=TA_CENTER)),
    ]], colWidths=[528])
    vb.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), banner_bg),
        ("BOX", (0, 0), (-1, -1), 1.2, banner_fg),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(vb)
    severity_tier = data.get("severity_tier") or "Safe"
    if mode != "QUICK":
        story.append(Paragraph(
            f"Severity <font color='{_severity_color(severity_tier).hexval()}'><b>{severity_tier.upper()}</b></font>",
            ParagraphStyle("SevTier", fontSize=8, leading=11, textColor=MUTED, alignment=TA_CENTER, spaceBefore=3),
        ))
    story.append(Spacer(1, 8))

    # ── Device snapshot ──
    story.append(Paragraph(f"Device snapshot — <b>{name}</b>", S["h2"]))
    snap = Table([
        [Paragraph("<b>Model</b>", S["small"]), Paragraph(name, S["cell"]),
         Paragraph("<b>Mode</b>", S["small"]), Paragraph(mode, S["cell"])],
        [Paragraph("<b>Serial</b>", S["small"]), Paragraph(f"<font face='Courier' size='7.5'>{serial}</font>", S["cell"]),
         Paragraph("<b>OS / Patch</b>", S["small"]), Paragraph(
             f"{device.get('android_version') or device.get('os_version') or '—'} · {device.get('security_patch') or '—'}", S["cell"])],
        [Paragraph("<b>IMEI</b>", S["small"]), Paragraph(f"{mask(device.get('imei'))} / {mask(device.get('imei_slot2'))}", S["cell"]),
         Paragraph("<b>SIM</b>", S["small"]), Paragraph(f"{device.get('sim_operator') or '—'} / {device.get('sim_operator_slot2') or '—'}", S["cell"])],
        [Paragraph("<b>Phone</b>", S["small"]), Paragraph(f"{mask(device.get('phone_number'))} / {mask(device.get('phone_number_slot2'))}", S["cell"]),
         Paragraph("<b>Security</b>", S["small"]), Paragraph(
             f"Lock {'YES' if device.get('screen_lock_enabled') else 'NO'} · Enc {'YES' if device.get('encryption_enabled') else 'NO'}", S["cell"])],
    ], colWidths=[70, 194, 80, 184])
    snap.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("BACKGROUND", (0, 0), (0, -1), PANEL_BG),
        ("BACKGROUND", (2, 0), (2, -1), PANEL_BG),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(snap)
    story.append(Spacer(1, 8))

    # ── Executive summary line ──
    story.append(Paragraph("Executive summary", S["h2"]))
    story.append(Paragraph(_executive_summary(data, checklist, apps), S["body"]))
    story.append(Spacer(1, 8))

    # ── CVE / risk one-liner ──
    story.append(Paragraph("Vulnerability &amp; app posture", S["h2"]))
    cve_line = "CVE lookup unavailable." if cve_meta.get("error") else (
        f"<b>{cve_meta.get('total_unpatched', len(cves))}</b> unpatched CVE(s) "
        f"({cve_meta.get('critical_count', 0)} critical · {cve_meta.get('high_count', 0)} high) — level <b>{cve_meta.get('overall_level', '—')}</b>."
        if cves else "No known unpatched CVEs beyond the current security patch."
    )
    if cve_meta.get("os_eol"):
        cve_line += f" <font color='#B91C1C'><b>OS is end-of-life ({cve_meta.get('os_eol_details', '')}).</b></font>"
    story.append(Paragraph(cve_line, S["body"]))
    story.append(Paragraph(
        f"{len(apps)} packages analyzed — {crit_apps} critical · "
        f"{sum(1 for a in apps if (a.get('risk_level') or '').upper() == 'HIGH')} high. "
        f"Top risk: {apps[0].get('package_name') if apps else '—'}.",
        S["body"],
    ))
    story.append(Spacer(1, 8))

    # ── Checklist summary (counts by category) ──
    story.append(Paragraph("Checklist outcome", S["h2"]))
    cat_sum: Dict[str, List[int]] = {}
    for c in checklist:
        key = _cat_label(c.get("category", ""))[:18]
        row = cat_sum.setdefault(key, [0, 0, 0])
        st = c.get("status")
        if st == "FAIL":
            row[2] += 1
        elif st == "WARNING":
            row[1] += 1
        else:
            row[0] += 1
    sum_rows = [[Paragraph("<b>Category</b>", S["cell"]), Paragraph("<b>Pass</b>", S["cell"]),
                 Paragraph("<b>Warn</b>", S["cell"]), Paragraph("<b>Fail</b>", S["cell"])]]
    for k, (p, w, f) in cat_sum.items():
        sum_rows.append([
            Paragraph(k, S["cell"]),
            Paragraph(f"<font color='{PASS_C.hexval()}'><b>{p}</b></font>", S["cell"]),
            Paragraph(f"<font color='{WARN_C.hexval()}'><b>{w}</b></font>", S["cell"]),
            Paragraph(f"<font color='{FAIL_C.hexval()}'><b>{f}</b></font>", S["cell"]),
        ])
    if len(sum_rows) > 1:
        sum_table = Table(sum_rows, colWidths=[280, 90, 80, 78])
        sum_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PANEL_BG),
            ("GRID", (0, 0), (-1, -1), 0.4, LINE),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(sum_table)
        story.append(Spacer(1, 8))
    else:
        story.append(Paragraph("No checklist data available.", S["body"]))
        story.append(Spacer(1, 8))

    # ── Signature / footer ── (teal accent bookends the page, matching the header's teal rule)
    story.append(HRFlowable(width="100%", thickness=1.5, color=TEAL, spaceBefore=2, spaceAfter=6))
    foot = Table([[
        Paragraph(f"Report {scan_id} · {mode} · Generated {ts}", S["small"]),
        Paragraph("CONFIDENTIAL — For internal BYOD admission auditing", S["small"]),
    ]], colWidths=[330, 198])
    foot.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(foot)

    doc.build(story)
    return output_filepath
