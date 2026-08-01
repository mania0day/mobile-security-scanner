from shared.exceptions import ScannerException


class APKInventoryException(ScannerException):
    """Raised when APK inventory collection fails."""


class PackageListError(APKInventoryException):
    """Raised when `adb shell pm list packages` returns unexpected output."""
