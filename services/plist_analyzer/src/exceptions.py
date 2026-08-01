class AnalyzerException(Exception):
    """Base exception for PList analyzer"""
    pass

class PlistParseError(AnalyzerException):
    """Error parsing Info.plist"""
    pass

class EntitlementsParseError(AnalyzerException):
    """Error parsing entitlements"""
    pass
