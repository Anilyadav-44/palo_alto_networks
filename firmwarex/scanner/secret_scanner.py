"""
Project Unit42-FirmwareX — Hardcoded Secrets & Credentials Scanner
Scans firmware files and binaries for embedded credentials, API keys, and certificates (PRD FR-1.5).
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple
import uuid

from firmwarex.schema import (
    VulnerabilityFinding, Category, RiskRating, Confidence, Architecture
)
from firmwarex.unpacker.entropy import EntropyAnalyzer
from firmwarex.scanner.redactor import SecretRedactor

SECRET_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "pattern": r"(AKIA[0-9A-Z]{16})",
        "cwe": "CWE-798",
        "risk": RiskRating.CRITICAL,
        "min_entropy": 3.0
    },
    {
        "name": "Generic API / Private Secret Key",
        "pattern": r"(?:api[_-]?key|secret[_-]?key|access[_-]?token)[\s=:'\"]{1,4}([A-Za-z0-9_\-\.]{20,64})",
        "cwe": "CWE-798",
        "risk": RiskRating.HIGH,
        "min_entropy": 3.2
    },
    {
        "name": "Hardcoded Configuration Password",
        "pattern": r"(?:password|passwd|pwd)[\s=:'\"]{1,4}([A-Za-z0-9_@#!$%^&*]{6,32})",
        "cwe": "CWE-259",
        "risk": RiskRating.HIGH,
        "min_entropy": 2.2
    },
    {
        "name": "RSA / EC Private Key Block",
        "pattern": r"(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END (?:RSA |EC )?PRIVATE KEY-----)",
        "cwe": "CWE-321",
        "risk": RiskRating.CRITICAL,
        "min_entropy": 4.0
    },
    {
        "name": "JSON Web Token (JWT)",
        "pattern": r"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
        "cwe": "CWE-798",
        "risk": RiskRating.HIGH,
        "min_entropy": 4.0
    }
]

class SecretScanner:
    """Scans all extracted firmware files for credentials and keys, with 100% redaction"""

    @classmethod
    def scan_directory(cls, rootfs_dir: Path, firmware_id: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        root_path = Path(rootfs_dir).resolve()

        if not root_path.exists():
            return findings

        # Scan files (limiting size per file to 5MB to avoid hanging on massive blobs)
        for file_path in root_path.rglob("*"):
            if not file_path.is_file():
                continue
            
            try:
                size = file_path.stat().st_size
                if size == 0 or size > 5 * 1024 * 1024:
                    continue

                rel_path = f"/{file_path.relative_to(root_path).as_posix()}"

                with open(file_path, "rb") as f:
                    content_bytes = f.read()

                # Extract strings and inspect
                text_content = content_bytes.decode("utf-8", errors="ignore")
                
                for pat in SECRET_PATTERNS:
                    matches = re.finditer(pat["pattern"], text_content, re.IGNORECASE)
                    for match in matches:
                        raw_secret = match.group(1).strip()
                        
                        # Calculate entropy of extracted secret to prune false positives
                        secret_entropy = EntropyAnalyzer.calculate_block_entropy(raw_secret.encode())
                        if secret_entropy < pat["min_entropy"]:
                            continue

                        # Redact and fingerprint immediately (100% Redaction guarantee)
                        redacted_secret, fingerprint = SecretRedactor.redact_and_fingerprint(raw_secret)

                        finding = VulnerabilityFinding(
                            vulnerability_id=str(uuid.uuid4()),
                            firmware_id=firmware_id,
                            binary=rel_path,
                            architecture=Architecture.UNKNOWN,
                            category=Category.HARDCODED_SECRET,
                            cwe=pat["cwe"],
                            address=None,
                            sink=None,
                            source=f"embedded_filesystem_file:{file_path.name}",
                            tainted_path=[],
                            crash_state=None,
                            risk_rating=pat["risk"],
                            confidence=Confidence.CONFIRMED,
                            evidence_ref=f"Hardcoded {pat['name']} discovered in file: {redacted_secret} (Fingerprint: {fingerprint})",
                            redacted=True
                        )
                        findings.append(finding)

            except Exception:
                continue

        return findings
