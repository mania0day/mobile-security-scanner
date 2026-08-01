class ScannerException(Exception):
    """Base exception for all Mobile Security Scanner services."""


class CommandError(ScannerException):
    """Raised when a system command fails and raise_on_error=True."""


class DeviceNotFoundError(ScannerException):
    """Raised when no Android device is detected via ADB."""


class InputNotReadyError(ScannerException):
    """
    Raised when a service tries to read a previous stage's output
    that does not exist yet (pipeline ordering violation).
    """


class AnalysisError(ScannerException):
    """Raised when a security analysis tool reports an unexpected failure."""