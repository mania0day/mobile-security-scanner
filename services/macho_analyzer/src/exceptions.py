class MachoAnalyzerError(Exception):
    """Base exception for MachoAnalyzer"""
    pass

class BinaryParsingError(MachoAnalyzerError):
    """Raised when parsing binary fails"""
    pass
