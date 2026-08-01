import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from shared.command import run_command
from shared.logger import get_logger
from shared.json_writer import read_json, write_json
from config import INVENTORY_OUTPUT_DIR, OUTPUT_DIR, ANALYSIS_TIMEOUT
from models import ApkidResult, ApkidFindings, ApkidSummary

logger = get_logger("APKID")


class ApkidService:
    """
    Runs APKiD on each extracted APK to detect packers, obfuscators,
    compilers, anti-debug and anti-VM techniques.
    """

    def run(self) -> None:
        logger.info("Starting APKID service (Parallel)")
        os.makedirs(OUTPUT_DIR, exist_ok=True)

        inventory_file = os.path.join(INVENTORY_OUTPUT_DIR, "extracted.json")
        if not os.path.exists(inventory_file):
            logger.error(f"extracted.json not found: {inventory_file}")
            sys.exit(1)

        inventory_data = read_json(inventory_file)
        items = inventory_data.get("results", []) if isinstance(inventory_data, dict) else inventory_data

        valid_items = [
            item for item in items
            if item.get("status") == "success" and item.get("local_path") and os.path.exists(item.get("local_path"))
        ]

        summary = ApkidSummary()

        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_item = {
                executor.submit(self._analyze, item.get("package_name", "unknown"), item.get("local_path")): item
                for item in valid_items
            }
            for future in as_completed(future_to_item):
                try:
                    result = future.result()
                    summary.results.append(result)
                    summary.total_analyzed += 1

                    if any([
                        result.findings.compiler, result.findings.obfuscator,
                        result.findings.anti_debug, result.findings.anti_vm,
                        result.findings.packer,
                    ]):
                        summary.total_with_findings += 1
                except Exception as exc:
                    logger.error(f"Apkid analysis exception: {exc}")

        output = {
            "total_analyzed": summary.total_analyzed,
            "total_with_findings": summary.total_with_findings,
            "results": [self._to_dict(r) for r in summary.results],
        }

        output_file = os.path.join(OUTPUT_DIR, "results.json")
        write_json(output_file, output)
        logger.info(f"APKID finished — {summary.total_analyzed} analyzed, {summary.total_with_findings} with findings")

    def _analyze(self, package_name: str, apk_path: str) -> ApkidResult:
        logger.info(f"  Scanning: {package_name}")
        result = ApkidResult(package_name=package_name, apk_path=apk_path)

        cmd = ["apkid", "--json", apk_path]
        try:
            proc = run_command(cmd, timeout=ANALYSIS_TIMEOUT)
            if proc.returncode != 0:
                cmd = [sys.executable, "-m", "apkid", "--json", apk_path]
                proc = run_command(cmd, timeout=ANALYSIS_TIMEOUT)

            if not proc.stdout.strip():
                logger.warning(f"  Empty apkid output for {package_name}")
                return result

            raw = json.loads(proc.stdout)
            result.raw_output = raw
            result.findings = self._parse(raw)

        except Exception as e:
            try:
                cmd = [sys.executable, "-m", "apkid", "--json", apk_path]
                proc = run_command(cmd, timeout=ANALYSIS_TIMEOUT)
                if proc.stdout.strip():
                    raw = json.loads(proc.stdout)
                    result.raw_output = raw
                    result.findings = self._parse(raw)
                    return result
            except Exception:
                pass

            logger.error(f"  Error scanning {package_name}: {e}")
            result.error = str(e)

        return result

    def _parse(self, raw: dict) -> ApkidFindings:
        findings = ApkidFindings()
        for file_entry in raw.get("files", []):
            for _filename, matches in file_entry.get("results", {}).items():
                for match in matches:
                    ml = match.lower()
                    if "proguard" in ml or "dexguard" in ml or "obfuscat" in ml:
                        findings.obfuscator.append(match)
                    elif "anti-debug" in ml or "anti_debug" in ml:
                        findings.anti_debug.append(match)
                    elif "emulat" in ml or "anti-vm" in ml or "anti_vm" in ml:
                        findings.anti_vm.append(match)
                    elif "pack" in ml:
                        findings.packer.append(match)
                    else:
                        findings.compiler.append(match)
        return findings

    @staticmethod
    def _to_dict(r: ApkidResult) -> dict:
        return {
            "package_name": r.package_name,
            "apk_path": r.apk_path,
            "findings": {
                "compiler": r.findings.compiler,
                "obfuscator": r.findings.obfuscator,
                "anti_debug": r.findings.anti_debug,
                "anti_vm": r.findings.anti_vm,
                "packer": r.findings.packer,
            },
            "raw_output": r.raw_output,
            "error": r.error,
        }
