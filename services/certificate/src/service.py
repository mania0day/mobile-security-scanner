import zipfile
import traceback
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives import hashes

from shared.logger import get_logger
from models import CertificateResult, CertificateInfo, RiskFlags

logger = get_logger("CertificateAnalyzer")


class CertificateAnalyzer:
    def __init__(self):
        self.logger = logger

    def analyze(self, package_name: str, apk_path: str) -> CertificateResult:
        result = CertificateResult(package_name=package_name, apk_path=apk_path)

        try:
            cert_data = self._extract_cert_data(apk_path)
            if not cert_data:
                result.error = "No supported certificate found in APK"
                return result

            cert = self._parse_cert(cert_data)
            if not cert:
                result.error = "Failed to parse certificate"
                return result

            cert_info = self._extract_fields(cert)
            result.certificate = cert_info

            uses_weak_algorithm = any(
                alg in cert_info.signature_algorithm.lower() for alg in ["md5", "sha1"]
            )
            is_debug_cert = "Android Debug" in cert_info.subject or "android debug" in cert_info.subject.lower()

            result.risk_flags = RiskFlags(
                uses_weak_algorithm=uses_weak_algorithm,
                is_expired=cert_info.is_expired,
                is_debug_cert=is_debug_cert,
            )

        except Exception as e:
            self.logger.error(f"Error analyzing certificate for {package_name}: {e}")
            self.logger.debug(traceback.format_exc())
            result.error = str(e)

        return result

    def _extract_cert_data(self, apk_path: str):
        try:
            with zipfile.ZipFile(apk_path) as z:
                cert_files = [
                    f for f in z.namelist()
                    if f.startswith('META-INF/') and f.endswith(('.RSA', '.DSA', '.EC'))
                ]
                if not cert_files:
                    return None
                return z.read(cert_files[0])
        except Exception as e:
            self.logger.error(f"Failed to read ZIP: {e}")
            raise

    def _parse_cert(self, cert_data: bytes):
        try:
            certs = pkcs7.load_der_pkcs7_certificates(cert_data)
            if certs:
                return certs[0]
        except Exception:
            pass

        # Fallback to single PEM/DER X509 cert loading
        try:
            return x509.load_der_x509_certificate(cert_data)
        except Exception:
            pass

        try:
            return x509.load_pem_x509_certificate(cert_data)
        except Exception as e:
            self.logger.error(f"Failed to parse X509 cert: {e}")
            raise

    def _extract_fields(self, cert: x509.Certificate) -> CertificateInfo:
        try:
            subject_str = cert.subject.rfc4514_string()
        except Exception:
            subject_str = str(cert.subject)

        try:
            issuer_str = cert.issuer.rfc4514_string()
        except Exception:
            issuer_str = str(cert.issuer)

        # Date handling
        if hasattr(cert, 'not_valid_before_utc'):
            not_before = cert.not_valid_before_utc
        else:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)

        if hasattr(cert, 'not_valid_after_utc'):
            not_after = cert.not_valid_after_utc
        else:
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        is_expired = not_after < now

        sig_alg = getattr(cert.signature_algorithm_oid, '_name', 'unknown')

        sha1_fp = cert.fingerprint(hashes.SHA1()).hex().lower()
        sha256_fp = cert.fingerprint(hashes.SHA256()).hex().lower()

        is_self_signed = subject_str == issuer_str

        return CertificateInfo(
            subject=subject_str,
            issuer=issuer_str,
            not_before=not_before.isoformat(),
            not_after=not_after.isoformat(),
            signature_algorithm=sig_alg,
            sha1_fingerprint=sha1_fp,
            sha256_fingerprint=sha256_fp,
            serial_number=str(cert.serial_number),
            is_expired=is_expired,
            is_self_signed=is_self_signed,
        )
