from shared.command import run_command
from shared.json_writer import read_json, write_json
from shared.logger import get_logger

from models import App, AppInventory
from config import ADB_OUTPUT_DIR, OUTPUT_DIR, ADB_TIMEOUT, INCLUDE_SYSTEM_APPS
from exceptions import PackageListError


class APKInventoryService:
    """
    Lists all installed packages on the connected Android device.

    Pipeline position: SECOND (after ADB service).
    Reads:  backend/output/adb/device.json
    Writes: backend/output/apk_inventory/apps.json

    Why two pm list commands?
    `pm list packages -3`  → user-installed apps only
    `pm list packages -s`  → system apps only
    Running both lets us categorize every app correctly.
    """

    def __init__(self):
        self.logger = get_logger("APKInventory")
        self.serial: str = ""
        self.apps: list[App] = []

    def run(self) -> None:
        self.logger.info("Starting APK Inventory service")

        self._load_device()
        self._collect_user_apps()

        if INCLUDE_SYSTEM_APPS:
            self._collect_system_apps()

        self._enrich_apps()
        self._save()

        self.logger.info(
            f"APK Inventory finished — {len(self.apps)} apps found"
        )

    # ------------------------------------------------------------------
    # Private methods
    # ------------------------------------------------------------------

    def _load_device(self) -> None:
        """Read device serial from ADB service output."""
        device = read_json(f"{ADB_OUTPUT_DIR}/device.json")
        self.serial = device["serial"]
        self.logger.info(f"Target device: {self.serial}")

    def _adb(self, *args: str) -> str:
        """Run an adb shell command on the target device."""
        result = run_command(
            ["adb", "-s", self.serial, *args],
            timeout=ADB_TIMEOUT,
        )
        return result.stdout.strip()

    def _collect_user_apps(self) -> None:
        """Collect third-party (user-installed) apps."""
        self.logger.info("Listing user-installed packages...")
        output = self._adb("shell", "pm", "list", "packages", "-3")

        if not output and "error" in output.lower():
            raise PackageListError(f"pm list packages -3 failed: {output}")

        packages = self._parse_package_list(output)
        for pkg in packages:
            self.apps.append(App(package_name=pkg, is_system_app=False))

        self.logger.info(f"  → {len(packages)} user apps")

    def _collect_system_apps(self) -> None:
        """Collect system/pre-installed apps."""
        self.logger.info("Listing system packages...")
        output = self._adb("shell", "pm", "list", "packages", "-s")

        packages = self._parse_package_list(output)

        # Avoid duplicates (some packages appear in both lists)
        existing = {app.package_name for app in self.apps}
        for pkg in packages:
            if pkg not in existing:
                self.apps.append(App(package_name=pkg, is_system_app=True))

        self.logger.info(f"  → {len(packages)} system apps")

    def _parse_package_list(self, output: str) -> list[str]:
        """
        Parse `pm list packages` output into a list of package names.

        Input format (one per line):  package:com.example.app
        Output:                       ['com.example.app', ...]
        """
        packages = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                packages.append(line[len("package:"):])
        return packages

    def _enrich_apps(self) -> None:
        """
        Collect version info and APK paths for each app.

        Why enrich separately?
        Running one `adb shell dumpsys package <name>` per app is slow
        for 200+ packages. We only fetch what we need: version and paths.
        """
        self.logger.info(f"Enriching {len(self.apps)} apps with version info...")

        for i, app in enumerate(self.apps):
            if i % 20 == 0:
                self.logger.info(f"  Processing {i}/{len(self.apps)}...")

            # Get version info
            dump = self._adb(
                "shell", "dumpsys", "package", app.package_name
            )
            app.version_name = self._extract_field(dump, "versionName=")
            app.version_code = self._extract_field(dump, "versionCode=")
            app.installer = self._extract_field(dump, "installerPackageName=")

            # Get APK path(s) — handles split APKs
            path_output = self._adb("shell", "pm", "path", app.package_name)
            app.apk_paths = [
                line.strip().replace("package:", "")
                for line in path_output.splitlines()
                if line.strip().startswith("package:")
            ]

    def _extract_field(self, text: str, prefix: str) -> str:
        """Extract a single-line field value from dumpsys output."""
        for line in text.splitlines():
            line = line.strip()
            if line.startswith(prefix):
                return line[len(prefix):].split()[0]
        return ""

    def _save(self) -> None:
        user_apps = [a for a in self.apps if not a.is_system_app]
        system_apps = [a for a in self.apps if a.is_system_app]

        payload = {
            "device_serial": self.serial,
            "total_count": len(self.apps),
            "user_app_count": len(user_apps),
            "system_app_count": len(system_apps),
            "apps": [
                {
                    "package_name": app.package_name,
                    "is_system_app": app.is_system_app,
                    "version_name": app.version_name,
                    "version_code": app.version_code,
                    "installer": app.installer,
                    "apk_paths": app.apk_paths,
                }
                for app in self.apps
            ],
        }

        write_json(f"{OUTPUT_DIR}/apps.json", payload)
        self.logger.info(f"Saved → {OUTPUT_DIR}/apps.json")
