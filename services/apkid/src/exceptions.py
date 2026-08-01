from shared.exceptions import ScannerException, AnalysisError

class ApkidException(ScannerException):
    """Base exception for APKiD service."""
    pass

class ApkidAnalysisError(AnalysisError):
    """Raised when APKiD analysis fails."""
    pass
