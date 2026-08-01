from shared.exceptions import ScannerException, AnalysisError

class AndroguardAnalysisError(AnalysisError):
    """Exception raised when Androguard fails to analyze an APK."""
    pass
