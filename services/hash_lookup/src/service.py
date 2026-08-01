import os
import time
import hashlib
from typing import Dict, Any

from config import (
    INVENTORY_OUTPUT_DIR,
    OUTPUT_DIR,
    VT_ENABLED,
    VT_API_KEY,
    VT_MAX_QUERIES,
    VT_THROTTLE_SECONDS,
    VT_TIMEOUT,
)
from shared.logger import get_logger
from shared.json_writer import read_json, write_json

logger = get_logger("HashLookup")


def hash_file(path: str) -> Dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def vt_lookup(sha256: str, api_key: str) -> Dict[str, Any]:
    """
    Queries VirusTotal v3 API for the given file SHA256.
    Handles rate limits (429) gracefully and never hangs the pipeline.
    """
    try:
        import requests
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=VT_TIMEOUT,
        )
        if r.status_code == 404:
            return {"found": False}
        if r.status_code == 429:
            logger.warning("VirusTotal API rate limit exceeded (429). Skipping remaining VT queries.")
            return {"error": "Rate limit exceeded (429)", "rate_limited": True}
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
        return {"error": f"VT API HTTP {r.status_code}"}
    except ImportError:
        return {"error": "requests not installed — VT lookup unavailable"}
    except Exception as e:
        return {"error": str(e)}


def run_hash_lookup():
    logger.info("Starting hash lookup service")

    input_path = os.path.join(INVENTORY_OUTPUT_DIR, "extracted.json")
    if not os.path.exists(input_path):
        logger.warning(f"Input file not found: {input_path}")
        return

    data = read_json(input_path)
    if not data or "results" not in data:
        logger.error("Invalid input data in extracted.json")
        return

    extracted_apps = data.get("results", [])

    out_data = {
        "total_analyzed": len(extracted_apps),
        "vt_lookup_enabled": bool(VT_ENABLED and VT_API_KEY),
        "results": []
    }

    vt_rate_limited = False
    vt_call_count = 0
    total = len(extracted_apps)

    for idx, apk in enumerate(extracted_apps, start=1):
        pkg_name = apk.get("package_name", "unknown")
        apk_path = apk.get("local_path", "")

        result_item = {
            "package_name": pkg_name,
            "apk_path": apk_path,
            "file_size_bytes": 0,
            "hashes": {},
            "virustotal": None,
            "error": ""
        }

        if VT_ENABLED and VT_API_KEY:
            logger.info(f"[{idx}/{total}] {pkg_name} — computing hashes + VirusTotal lookup")
        else:
            logger.info(f"[{idx}/{total}] {pkg_name} — computing local hashes (VT disabled in this mode)")

        if apk_path and os.path.exists(apk_path):
            result_item["file_size_bytes"] = os.path.getsize(apk_path)
            try:
                hashes = hash_file(apk_path)
                result_item["hashes"] = hashes

                # VirusTotal Lookup (only in deep mode, capped, and not rate limited)
                if VT_ENABLED and VT_API_KEY and not vt_rate_limited and vt_call_count < VT_MAX_QUERIES:
                    # Free VT API tier is limited to ~4 req/min. Throttle to avoid 429.
                    if vt_call_count > 0:
                        time.sleep(VT_THROTTLE_SECONDS)

                    vt_res = vt_lookup(hashes["sha256"], VT_API_KEY)
                    result_item["virustotal"] = vt_res
                    vt_call_count += 1
                    logger.info(f"[{idx}/{total}] {pkg_name} — VT result: {vt_res.get('found', False) and 'seen' or vt_res.get('error', 'unknown')}")

                    if vt_res.get("rate_limited"):
                        vt_rate_limited = True
                        logger.warning("VirusTotal rate limit hit — stopping further VT lookups")

            except Exception as e:
                result_item["error"] = str(e)
                logger.warning(f"[{idx}/{total}] {pkg_name} — error: {e}")
        else:
            result_item["error"] = "APK file not found"
            logger.warning(f"[{idx}/{total}] {pkg_name} — APK file not found at {apk_path}")

        out_data["results"].append(result_item)

    if VT_ENABLED and VT_API_KEY and vt_call_count >= VT_MAX_QUERIES:
        logger.info(f"Reached VT_MAX_QUERIES ({VT_MAX_QUERIES}); remaining packages skipped for VT lookup")

    output_path = os.path.join(OUTPUT_DIR, "results.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    write_json(output_path, out_data)
    logger.info(f"Finished hash lookup for {len(extracted_apps)} packages (VT queries: {vt_call_count})")
