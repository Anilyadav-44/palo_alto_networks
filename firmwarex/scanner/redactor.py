"""
Project Unit42-FirmwareX — Secret Redaction & Cryptographic Fingerprinting
Enforces 100% redaction of plaintext secrets before persistence (PRD Section 13.1 & Appendix A).
"""

import hashlib
from typing import Tuple

class SecretRedactor:
    """Masks discovered secrets and generates SHA-256 fingerprints"""

    @staticmethod
    def redact_and_fingerprint(secret: str, prefix_len: int = 4, suffix_len: int = 4) -> Tuple[str, str]:
        """
        Redacts secret text (e.g., 'AKIA1234567890EXAMPLE' -> 'AKIA*************MPLE')
        and returns (redacted_str, fingerprint_hash).
        """
        if not secret:
            return "", ""

        # Compute SHA-256 fingerprint of the raw secret
        hasher = hashlib.sha256(secret.encode("utf-8", errors="ignore"))
        fingerprint = f"sha256:{hasher.hexdigest()[:16]}"

        s_len = len(secret)
        if s_len <= (prefix_len + suffix_len):
            redacted = "*" * s_len
        else:
            redacted = secret[:prefix_len] + ("*" * (s_len - prefix_len - suffix_len)) + secret[-suffix_len:]

        return redacted, fingerprint
