class CertificateException(Exception):
    """Base exception for certificate service"""
    pass

class ExtractionError(CertificateException):
    """Raised when certificate extraction fails"""
    pass
