"""
Unit Tests — Static Hardening Audit & Dangerous Sinks (PRD FR-1.3, FR-1.4, FR-1.5)
"""

import pytest
from pathlib import Path
from firmwarex.audit.elf_parser import ELFInspector
from firmwarex.audit.checksec import HardeningAuditor
from firmwarex.audit.dangerous_sinks import DangerousSinksScanner
from firmwarex.schema import Category, RiskRating

def test_elf_inspector():
    httpd_bin = Path("data_storage/extracted/test_fw_001/bin/httpd")
    assert httpd_bin.exists()

    info = ELFInspector.inspect(httpd_bin)
    assert info["is_elf"] is True
    assert "MIPS" in info["architecture"]
    assert info["bits"] == 32
    assert "main" in info["symbols"]
    assert "strcpy" in info["symbols"] or "strcpy" in info["imported_functions"]

def test_checksec_mitigations():
    httpd_bin = Path("data_storage/extracted/test_fw_001/bin/httpd")
    record = HardeningAuditor.audit_binary(httpd_bin, "/bin/httpd")
    
    assert record.path == "/bin/httpd"
    assert "MIPS" in record.architecture
    assert record.nx is False # httpd was crafted without NX
    assert record.pie is False
    assert record.stack_canary is False
    assert record.risk_score > 5.0 # Unhardened binary has elevated risk score

def test_dangerous_sinks_scanner():
    httpd_bin = Path("data_storage/extracted/test_fw_001/bin/httpd")
    findings = DangerousSinksScanner.scan_binary(
        file_path=httpd_bin,
        firmware_id="test_fw_001",
        rootfs_rel_path="/bin/httpd",
        arch="MIPS"
    )
    
    assert len(findings) >= 2
    cwes = [f.cwe for f in findings]
    sinks = [f.sink for f in findings]

    assert "CWE-120" in cwes # strcpy
    assert "CWE-78" in cwes  # system
    assert "strcpy" in sinks
    assert "system" in sinks
