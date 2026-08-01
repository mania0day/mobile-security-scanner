"""
Mobile Security Scanner — Orchestrator (Parallel Container Pipeline Stage Execution)

The orchestrator controls the entire scan pipeline (Android & iOS).
It auto-identifies connected USB devices (Android vs. iPhone) and runs
non-dependent microservices concurrently in parallel stages.

Usage:
    python orchestrator.py                     # Auto-detects device & runs minimal scan
    python orchestrator.py --mode deep         # Auto-detects device & runs deep scan
    python orchestrator.py --platform android  # Force Android scan
    python orchestrator.py --platform ios      # Force iOS scan
"""
import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from pipeline import (
    ANDROID_MINIMAL_PIPELINE,
    ANDROID_DEEP_PIPELINE,
    IOS_MINIMAL_PIPELINE,
    IOS_DEEP_PIPELINE,
)
from runner import ServiceRunner
from config import PROJECT_ROOT, COMPOSE_FILE
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | Orchestrator | %(message)s",
)
logger = logging.getLogger("Orchestrator")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mobile Security Scanner — Orchestrator (Android & iOS Auto-Detect)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--platform",
        choices=["auto", "android", "ios"],
        default="auto",
        help="Target platform: auto (default auto-detects USB device), android, or ios",
    )
    parser.add_argument(
        "--mode",
        choices=["minimal", "deep"],
        default="minimal",
        help="Scan mode: minimal (offline) or deep (requires API keys)",
    )
    parser.add_argument(
        "--skip",
        nargs="*",
        default=[],
        metavar="SERVICE",
        help="Services to skip (e.g. --skip mobsf yara)",
    )
    parser.add_argument(
        "--serial",
        default="",
        metavar="SERIAL",
        help="Scan a specific connected device serial (skips auto-detection of first device)",
    )
    return parser.parse_args()


def detect_platform(runner: ServiceRunner) -> tuple[str, list[str]]:
    logger.info("🔍 Auto-detecting connected USB mobile device...")

    logger.info("  [1/2] Checking for Android device via ADB...")
    adb_ok = runner.run_service("adb")
    if adb_ok:
        device_json = Path(PROJECT_ROOT) / "backend" / "output" / "adb" / "device.json"
        serial = "Unknown"
        model = "Android"
        if device_json.exists():
            try:
                data = json.loads(device_json.read_text())
                serial = data.get("serial", "Unknown")
                model = f"{data.get('manufacturer', '')} {data.get('model', '')}".strip() or "Android"
            except Exception:
                pass

        logger.info(f"  ✅ ANDROID DEVICE DETECTED: {model} (Serial: {serial})")
        return "android", ["adb"]

    logger.info("  [2/2] Checking for iOS device (iPhone/iPad) via usbmux...")
    ios_ok = runner.run_service("ios_device")
    if ios_ok:
        device_json = Path(PROJECT_ROOT) / "backend" / "output" / "ios_device" / "device.json"
        udid = "Unknown"
        dev_name = "iPhone"
        if device_json.exists():
            try:
                data = json.loads(device_json.read_text())
                udid = data.get("udid", "Unknown")
                dev_name = data.get("device_name", "iPhone")
            except Exception:
                pass

        logger.info(f"  ✅ iOS DEVICE DETECTED: {dev_name} (UDID: {udid})")
        return "ios", ["ios_device"]

    return "none", []


def get_pipeline_for_platform(platform: str, mode: str) -> list[str]:
    if platform == "ios":
        return list(IOS_DEEP_PIPELINE if mode == "deep" else IOS_MINIMAL_PIPELINE)
    else:
        return list(ANDROID_DEEP_PIPELINE if mode == "deep" else ANDROID_MINIMAL_PIPELINE)


def main() -> int:
    args = parse_args()
    runner = ServiceRunner(
        project_root=PROJECT_ROOT,
        compose_file=COMPOSE_FILE,
        env={
            "SCAN_MODE": args.mode,
            "VT_ENABLED": "1" if args.mode == "deep" else "0",
            "ADB_SERIAL": args.serial,
        },
    )

    already_run = []

    if args.serial:
        # Scan a specific connected device: resolve platform from ADB, no auto-detect
        logger.info(f"🎯 Scanning specified device serial: {args.serial}")
        platform_name = args.platform
        if platform_name == "auto":
            # Default to android when a specific serial is requested (adb)
            platform_name = "android"
    elif args.platform == "auto":
        platform_name, already_run = detect_platform(runner)
        if platform_name == "none":
            logger.error("\n❌ NO CONNECTED DEVICE DETECTED OVER USB.")
            return 1
    else:
        platform_name = args.platform

    pipeline = get_pipeline_for_platform(platform_name, args.mode)

    # Gate VirusTotal lookups to deep scans only (free tier: ~4 req/min, 15s sleep each)
    os.environ["VT_ENABLED"] = "1" if args.mode == "deep" else "0"
    os.environ["SCAN_MODE"] = args.mode

    if args.skip:
        pipeline = [s for s in pipeline if s not in args.skip]

    logger.info("=" * 60)
    logger.info(f" 🚀 MOBILE SECURITY SCANNER — [{platform_name.upper()} PIPELINE]")
    logger.info(f" Platform : {platform_name.upper()}")
    logger.info(f" Mode     : {args.mode.upper()}")
    logger.info(f" Pipeline : {' -> '.join(pipeline)}")
    logger.info("=" * 60)

    start_time = time.time()
    failed_services = []

    # Partition Pipeline into 3 Parallel Execution Stages
    # Stage 1: Collection Services (Must run sequentially first)
    stage1_services = [s for s in ["adb", "ios_device", "apk_inventory", "apk_extractor"] if s in pipeline]
    
    # Stage 2: Independent Analysis Services (Can run concurrently in parallel)
    stage2_parallel = [
        s for s in ["apkid", "androguard", "certificate", "root_detection",
                    "cve_checker",
                    "hash_lookup", "yara", "mobsf", "mvt", "plist_analyzer", 
                    "macho_analyzer", "ios_certificate", "jailbreak_detection"] 
        if s in pipeline
    ]
    
    # Stage 3: Dependent & Aggregation Services (Permission analyzer, Risk engine, Report generator)
    stage3_dependent = [s for s in ["permission_analyzer", "risk_engine", "report_generator"] if s in pipeline]

    # --- STAGE 1 EXECUTION ---
    logger.info("\n--- [STAGE 1/3] Device Data Collection ---")
    for s in stage1_services:
        if s in already_run:
            logger.info(f"✓ {s} already completed during auto-detection")
            continue
        logger.info(f"Running collection service: {s}")
        if not runner.run_service(s):
            logger.error(f"Critical collection service '{s}' failed. Stopping scanner.")
            return 1
        logger.info(f"✓ {s} completed")

    # --- STAGE 2 PARALLEL EXECUTION ---
    logger.info("\n--- [STAGE 2/3] Parallel Microservice Static Analysis ---")
    
    def execute_service(service_name: str) -> tuple[str, bool]:
        logger.info(f"⚡ Launching parallel container: {service_name}")
        ok = runner.run_service(service_name)
        return service_name, ok

    androguard_ok = False

    if stage2_parallel:
        remaining = set(stage2_parallel)
        heartbeat_stop = threading.Event()

        def _heartbeat():
            while not heartbeat_stop.is_set():
                done = len(stage2_parallel) - len(remaining)
                total = len(stage2_parallel)
                names = ", ".join(sorted(remaining))
                logger.info(f"  ⏳ [{done}/{total}] services done — waiting for: {names}")
                heartbeat_stop.wait(15)

        hb = threading.Thread(target=_heartbeat, daemon=True)
        hb.start()

        with ThreadPoolExecutor(max_workers=min(len(stage2_parallel), 6)) as executor:
            future_map = {executor.submit(execute_service, s): s for s in stage2_parallel}
            for future in as_completed(future_map):
                srv_name, ok = future.result()
                remaining.discard(srv_name)
                if ok:
                    logger.info(f"  ✓ {srv_name} completed")
                    if srv_name == "androguard":
                        androguard_ok = True
                else:
                    logger.error(f"  ✗ {srv_name} FAILED")
                    failed_services.append(srv_name)

        heartbeat_stop.set()
        hb.join(timeout=5)

    # Run permission_analyzer as soon as androguard completes if required
    if "permission_analyzer" in stage3_dependent:
        logger.info("\nRunning permission_analyzer...")
        if runner.run_service("permission_analyzer"):
            logger.info("  ✓ permission_analyzer completed")
        else:
            logger.error("  ✗ permission_analyzer FAILED")
            failed_services.append("permission_analyzer")

    # --- STAGE 3 AGGREGATION & REPORTING ---
    logger.info("\n--- [STAGE 3/3] Risk Aggregation & Report Generation ---")
    for s in ["risk_engine", "report_generator"]:
        if s in stage3_dependent:
            logger.info(f"Running: {s}")
            if runner.run_service(s):
                logger.info(f"  ✓ {s} completed")
            else:
                logger.error(f"  ✗ {s} FAILED")
                failed_services.append(s)

    elapsed = time.time() - start_time

    logger.info("\n" + "=" * 60)
    logger.info(f" 📊 {platform_name.upper()} Scan completed in {elapsed:.1f}s")
    if failed_services:
        logger.warning(f" Failed services: {', '.join(failed_services)}")
    else:
        logger.info(" All pipeline services completed successfully!")
    logger.info(f" Reports available at: {PROJECT_ROOT}/backend/output/reports/")
    logger.info("=" * 60)

    return 1 if failed_services else 0


if __name__ == "__main__":
    sys.exit(main())
