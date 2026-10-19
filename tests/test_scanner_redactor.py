"""
Unit Tests — Secret Redaction, Credential Scanning & Crypto Audit (PRD Section 13.1 & Appendix B)
"""

from pathlib import Path
from firmwarex.scanner.redactor import SecretRedactor
from firmwarex.scanner.secret_scanner import SecretScanner
from firmwarex.scanner.crypto_scanner import CryptoScanner
from firmwarex.schema import Category, RiskRating

def test_secret_redactor_masking():
    raw_key = "AKIAIOSFODNN7EXAMPLE"
    redacted, fingerprint = SecretRedactor.redact_and_fingerprint(raw_key)
    
    assert "AKIA" in redacted
    assert "MPLE" in redacted
    assert "********" in redacted
    assert raw_key not in redacted # Raw secret is never preserved
    assert fingerprint.startswith("sha256:")

def test_secret_scanner_detection():
    extracted_dir = Path("data_storage/extracted/test_fw_001")
    assert extracted_dir.exists()

    findings = SecretScanner.scan_directory(extracted_dir, "test_fw_001")
    assert len(findings) >= 2

    cwes = [f.cwe for f in findings]
    assert "CWE-798" in cwes or "CWE-321" in cwes or "CWE-259" in cwes

    for f in findings:
        assert f.redacted is True
        assert f.category == Category.HARDCODED_SECRET
        # Verify no plaintext secret in evidence
        assert "AKIAIOSFODNN7EXAMPLE" not in f.evidence_ref

def test_crypto_scanner_detection():
    symbols = ["MD5_Init", "DES_ecb_encrypt", "malloc", "free"]
    findings = CryptoScanner.scan_binary_crypto(
        firmware_id="test_fw_001",
        binary_rel_path="/bin/httpd",
        arch="MIPS",
        symbols=symbols
    )

    assert len(findings) >= 2
    cwes = [f.cwe for f in findings]
    assert "CWE-328" in cwes # MD5
    assert "CWE-327" in cwes # DES
