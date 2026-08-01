from shared.exceptions import ScannerException


class MobSFException(ScannerException):
    """Raised when MobSF service fails."""


class MobSFConnectionError(MobSFException):
    """Raised when the MobSF server cannot be reached."""


class MobSFUploadError(MobSFException):
    """Raised when APK upload to MobSF fails."""


class MobSFScanError(MobSFException):
    """Raised when MobSF scan request fails."""
