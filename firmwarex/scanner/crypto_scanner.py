"""
Project Unit42-FirmwareX — Deprecated Cryptography & Weak Hash Scanner
Detects obsolete cryptographic primitives and insecure hash algorithms (PRD Section 5.1 & Appendix B).
"""

from pathlib import Path
from typing import List, Dict, Any
import uuid

from firmwarex.schema import (
    VulnerabilityFinding, Category, RiskRating, Confidence, Architecture
)

WEAK_CRYPTO_PATTERNS = [
    {
        "name": "MD5 Hash Function",
        "symbols": ["MD5_Init", "MD5_Update", "MD5_Final", "EVP_md5", "md5_starts", "md5_process"],
        "cwe": "CWE-328",
        "risk": RiskRating.MEDIUM,
        "desc": "Use of cryptographically broken MD5 hash function"
    },
    {
        "name": "SHA-1 Hash Function",
        "symbols": ["SHA1_Init", "SHA1_Update", "SHA1_Final", "EVP_sha1", "sha1_starts"],
        "cwe": "CWE-328",
        "risk": RiskRating.LOW,
        "desc": "Use of deprecated SHA-1 hash function"
    },
    {
        "name": "DES / 3DES Cipher",
        "symbols": ["DES_ecb_encrypt", "DES_cbc_encrypt", "des_crypt", "DES_set_key", "EVP_des_ecb"],
        "cwe": "CWE-327",
        "risk": RiskRating.HIGH,
        "desc": "Use of obsolete DES/3DES cipher with insufficient key length"
    },
    {
        "name": "RC4 Stream Cipher",
        "symbols": ["RC4_set_key", "RC4", "arcfour_init", "EVP_rc4"],
        "cwe": "CWE-327",
        "risk": RiskRating.HIGH,
        "desc": "Use of vulnerable RC4 stream cipher"
    },
    {
        "name": "Electronic Codebook (ECB) Mode",
        "symbols": ["AES_ecb_encrypt", "EVP_aes_128_ecb", "EVP_aes_256_ecb"],
        "cwe": "CWE-327",
        "risk": RiskRating.MEDIUM,
        "desc": "Use of ECB encryption mode lacking semantic security"
    }
]

class CryptoScanner:
    """Scans ELF binaries and libraries for weak cryptography and broken hashing"""

    @classmethod
    def scan_binary_crypto(
        cls,
        firmware_id: str,
        binary_rel_path: str,
        arch: str,
        symbols: List[str]
    ) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []

        arch_enum = Architecture.UNKNOWN
        for a in Architecture:
            if a.value.lower() == arch.lower():
                arch_enum = a
                break

        sym_set = set(symbols)

        for pat in WEAK_CRYPTO_PATTERNS:
            matched_syms = [s for s in pat["symbols"] if s in sym_set]
            if matched_syms:
                finding = VulnerabilityFinding(
                    vulnerability_id=str(uuid.uuid4()),
                    firmware_id=firmware_id,
                    binary=binary_rel_path,
                    architecture=arch_enum,
                    category=Category.WEAK_CRYPTO,
                    cwe=pat["cwe"],
                    address=None,
                    sink=matched_syms[0],
                    source="crypto_library_linkage",
                    tainted_path=[],
                    crash_state=None,
                    risk_rating=pat["risk"],
                    confidence=Confidence.CONFIRMED,
                    evidence_ref=f"{pat['desc']} identified via linked symbols: {', '.join(matched_syms)}",
                    redacted=False
                )
                findings.append(finding)

        return findings
