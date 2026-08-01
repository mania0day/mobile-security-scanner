import os
from shared.logger import get_logger
from androguard.core.bytecodes.apk import APK
from models import ApkManifest, AndroguardResult

logger = get_logger("Androguard")


class AndroguardService:
    def __init__(self, timeout: int = 180):
        self.timeout = timeout

    def analyze_apk(self, apk_path: str, package_name: str) -> "AndroguardResult":
        logger.info(f"  Analyzing: {package_name}")

        try:
            if not os.path.exists(apk_path):
                raise FileNotFoundError(f"APK file not found: {apk_path}")

            a = APK(apk_path)

            def safe_list(val):
                return list(val) if val else []

            def safe_str(val):
                return str(val) if val is not None else ""

            # Safely check debuggable status
            is_debug = False
            if hasattr(a, 'is_debuggable'):
                try:
                    is_debug = bool(a.is_debuggable())
                except Exception:
                    is_debug = False

            manifest = ApkManifest(
                package=package_name,
                min_sdk=safe_str(a.get_min_sdk_version()),
                target_sdk=safe_str(a.get_target_sdk_version()),
                debuggable=is_debug,
                permissions=safe_list(a.get_permissions()),
                activities=safe_list(a.get_activities()),
                services=safe_list(a.get_services()),
                receivers=safe_list(a.get_receivers()),
                providers=safe_list(a.get_providers()),
                libraries=safe_list(a.get_libraries()),
            )

            return AndroguardResult(
                package_name=package_name,
                apk_path=apk_path,
                manifest=manifest,
            )

        except Exception as e:
            logger.error(f"  Error analyzing {package_name}: {e}")
            return AndroguardResult(package_name=package_name, apk_path=apk_path, error=str(e))
