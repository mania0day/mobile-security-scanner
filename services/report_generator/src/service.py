import os
import datetime
from jinja2 import Template
from shared.logger import get_logger
from shared.json_writer import read_json, write_json
from config import RISK_ENGINE_OUTPUT, ADB_OUTPUT, INVENTORY_OUTPUT, CVE_OUTPUT, OUTPUT_DIR
from pdf_generator import generate_pdf_report

logger = get_logger("ReportGenerator")

JINJA2_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mobile Security Admission Report — {{ device.get('serial', 'Unknown') }}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; }
  .container { max-width: 1100px; margin: 0 auto; }
  .header { background: #1e293b; border-radius: 12px; padding: 2rem; border: 1px solid #334155; margin-bottom: 2rem; }
  .title { font-size: 1.8rem; font-weight: 700; color: #38bdf8; margin-bottom: 0.5rem; }
  .verdict-badge { display: inline-block; padding: 0.5rem 1.2rem; border-radius: 8px; font-size: 1.2rem; font-weight: 800; text-transform: uppercase; margin-top: 0.5rem; }
  .verdict-PASS { background: #14532d; color: #4ade80; border: 1px solid #22c55e; }
  .verdict-CONDITIONAL { background: #713f12; color: #fde047; border: 1px solid #eab308; }
  .verdict-FAIL { background: #7f1d1d; color: #fca5a5; border: 1px solid #ef4444; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }
  .card { background: #1e293b; border-radius: 10px; padding: 1.5rem; border: 1px solid #334155; }
  .card-title { font-size: 0.9rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 1rem; }
  table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
  th, td { text-align: left; padding: 0.75rem 1rem; border-bottom: 1px solid #334155; font-size: 0.9rem; }
  th { background: #0f172a; color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; }
  .status-PASS { color: #4ade80; font-weight: 700; }
  .status-WARNING { color: #fde047; font-weight: 700; }
  .status-FAIL { color: #f87171; font-weight: 700; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="title">🔐 MOBILE SECURITY ADMISSION REPORT</div>
    <p style="color:#94a3b8">Enterprise BYOD Admission Audit & Security Assessment</p>
    <div class="verdict-badge verdict-{{ report.get('verdict', 'PASS') }}">
      ADMISSION VERDICT: {{ report.get('verdict', 'PASS') }}
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <div class="card-title">Overall Security Score</div>
      <div style="font-size: 3rem; font-weight: 800; color: #38bdf8">{{ report.overall_score }}<span style="font-size:1.2rem;color:#64748b">/100</span></div>
      <p style="margin-top:0.5rem;color:#94a3b8">Risk Level: <strong>{{ report.overall_level }}</strong></p>
    </div>
    <div class="card">
      <div class="card-title">Device Specifications</div>
      <p><strong>Serial:</strong> {{ device.get('serial', 'N/A') }}</p>
      <p><strong>Model:</strong> {{ device.get('manufacturer', '') }} {{ device.get('model', 'N/A') }}</p>
      <p><strong>OS:</strong> Android {{ device.get('android_version', 'N/A') }} (SDK {{ device.get('sdk', 'N/A') }})</p>
      <p><strong>Patch Level:</strong> {{ device.get('security_patch', 'N/A') }}</p>
    </div>
  </div>

  <div class="card" style="margin-bottom:2rem">
    <div class="card-title">Identity & SIM Details</div>
    <p><strong>Phone / SIM:</strong> {{ device.get('phone_number') or device.get('subscriber_id') or 'N/A' }}</p>
    <p><strong>IMEI (SIM 1):</strong> {{ device.get('imei') or 'N/A' }}</p>
    <p><strong>IMEI (SIM 2):</strong> {{ device.get('imei_slot2') or 'N/A' }}</p>
    <p><strong>SIM Operator:</strong> {{ device.get('sim_operator') or 'N/A' }}</p>
    <p><strong>SIM Serial:</strong> {{ device.get('sim_serial') or 'N/A' }}</p>
  </div>

  <div class="card" style="margin-bottom:2rem">
    <div class="card-title">8-Category Admission Security Checklist</div>
    <table>
      <thead>
        <tr><th>Category</th><th>Check Name</th><th>Priority</th><th>Status</th></tr>
      </thead>
      <tbody>
      {% for chk in report.checklist_evaluations %}
        <tr>
          <td>{{ chk.category }}</td>
          <td><strong>{{ chk.check_name }}</strong><br><span style="font-size:0.8rem;color:#94a3b8">{{ chk.details }}</span></td>
          <td>{{ chk.priority }}</td>
          <td class="status-{{ chk.status }}">{{ chk.status }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="card">
    <div class="card-title">Risky Applications (Top {{ report.top_risky_apps | length }})</div>
    <table>
      <thead>
        <tr><th>Package Name</th><th>Risk Score</th><th>Level</th><th>Risk Factors</th></tr>
      </thead>
      <tbody>
      {% for app in report.top_risky_apps %}
      {% if app.risk_score > 0 %}
        <tr>
          <td style="font-family:monospace">{{ app.package_name }}</td>
          <td>{{ app.risk_score }}</td>
          <td><strong style="color:#fde047">{{ app.risk_level }}</strong></td>
          <td style="color:#94a3b8">{{ app.risk_factors | join(', ') }}</td>
        </tr>
      {% endif %}
      {% endfor %}
      </tbody>
    </table>
  </div>
</div>
</body>
</html>"""

class ReportGeneratorService:
    def __init__(self):
        self.risk_assessment = {}
        self.device = {}
        self.apps = {}
        self.cve_data = {}
        self.report_data = {}

    def run(self):
        logger.info("Starting report generation")
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        self._load_data()
        self._generate_json_report()
        self._generate_html_report()
        self._generate_text_report()
        self._generate_pdf_report()
        logger.info("Report generation complete (JSON, HTML, TXT, PDF)")

    def _load_data(self):
        risk_file = os.path.join(RISK_ENGINE_OUTPUT, "risk_assessment.json")
        if os.path.exists(risk_file):
            self.risk_assessment = read_json(risk_file)
        else:
            logger.warning("No risk_assessment.json found")

        device_file = os.path.join(ADB_OUTPUT, "device.json")
        if os.path.exists(device_file):
            self.device = read_json(device_file)

        apps_file = os.path.join(INVENTORY_OUTPUT, "apps.json")
        if os.path.exists(apps_file):
            self.apps = read_json(apps_file)

        cve_file = os.path.join(CVE_OUTPUT, "results.json")
        if os.path.exists(cve_file):
            self.cve_data = read_json(cve_file)

    def _generate_json_report(self):
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        app_risks = self.risk_assessment.get("app_risks", [])
        sorted_apps = sorted(app_risks, key=lambda x: x.get("risk_score", 0), reverse=True)

        self.report_data = {
            "report_version": "1.0",
            "scan_timestamp": timestamp,
            "device_serial": self.device.get("serial") or self.risk_assessment.get("device_serial", ""),
            "device": self.device,
            "scan_mode": self.risk_assessment.get("scan_mode", "minimal"),
            "verdict": self.risk_assessment.get("verdict", "PASS"),
            "overall_score": self.risk_assessment.get("overall_score", 0),
            "overall_level": self.risk_assessment.get("overall_level", "LOW"),
            "checklist_evaluations": self.risk_assessment.get("checklist_evaluations", []),
            "cve_findings": self.cve_data or None,
            "summary": self.risk_assessment.get("summary", {}),
            "device_risk": self.risk_assessment.get("device_risk", {}),
            "top_risky_apps": sorted_apps[:10],
            "app_risks": sorted_apps,
            "all_apps": sorted_apps,
        }

        output_file = os.path.join(OUTPUT_DIR, "report.json")
        write_json(output_file, self.report_data)
        logger.info(f"Wrote JSON report to {output_file}")

    def _generate_html_report(self):
        template = Template(JINJA2_TEMPLATE)
        html_content = template.render(
            report=self.report_data,
            device=self.device
        )
        output_file = os.path.join(OUTPUT_DIR, "report.html")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logger.info(f"Wrote HTML report to {output_file}")

    def _generate_text_report(self):
        lines = []
        lines.append("=========================================")
        lines.append(" MOBILE SECURITY ADMISSION REPORT")
        lines.append("=========================================")

        device_str = f"{self.device.get('manufacturer', '')} {self.device.get('model', 'Unknown')}".strip()
        if not device_str:
            device_str = "Unknown Device"
        if self.device.get('serial'):
            device_str += f" ({self.device.get('serial')})"

        lines.append(f"Generated : {self.report_data.get('scan_timestamp')}")
        lines.append(f"Device    : {device_str}")
        lines.append(f"Phone/SIM : {self.device.get('phone_number') or self.device.get('subscriber_id') or 'N/A'}")
        lines.append(f"IMEI 1    : {self.device.get('imei') or 'N/A'}")
        lines.append(f"IMEI 2    : {self.device.get('imei_slot2') or 'N/A'}")
        lines.append(f"SIM OP    : {self.device.get('sim_operator') or 'N/A'}")
        lines.append(f"SIM SERIAL: {self.device.get('sim_serial') or 'N/A'}")
        lines.append(f"VERDICT   : {self.report_data.get('verdict', 'PASS')}")
        lines.append(f"OVERALL RISK: {self.report_data.get('overall_level', 'LOW')} (Score: {self.report_data.get('overall_score', 0)}/100)")
        lines.append("-----------------------------------------")
        lines.append("8-CATEGORY ADMISSION CHECKLIST:")
        for chk in self.report_data.get('checklist_evaluations', []):
            lines.append(f"  [{chk.get('status')}] {chk.get('category')} - {chk.get('check_name')} ({chk.get('priority')})")
            if chk.get('details'):
                lines.append(f"      Details: {chk.get('details')}")

        lines.append("-----------------------------------------")
        lines.append("Report files:")
        lines.append(f"  JSON: {os.path.join(OUTPUT_DIR, 'report.json')}")
        lines.append(f"  HTML: {os.path.join(OUTPUT_DIR, 'report.html')}")
        lines.append(f"  PDF : {os.path.join(OUTPUT_DIR, 'report.pdf')}")
        lines.append("=========================================")

        output_file = os.path.join(OUTPUT_DIR, "report.txt")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines) + "\n")
        logger.info(f"Wrote TXT report to {output_file}")

    def _generate_pdf_report(self):
        try:
            pdf_path = os.path.join(OUTPUT_DIR, "report.pdf")
            generate_pdf_report(self.report_data, pdf_path)
            logger.info(f"Wrote PDF report to {pdf_path}")
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
