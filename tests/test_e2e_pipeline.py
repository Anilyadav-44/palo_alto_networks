"""
End-to-End Pipeline Integration Test (PRD Week 4 & Section 13 Acceptance Criteria)
"""

from pathlib import Path
from firmwarex.pipeline.orchestrator import FirmwareAnalysisPipeline
from firmwarex.config import settings
from firmwarex.schema import FirmwareReport, RiskRating, Category

def test_full_pipeline_run():
    sample_fw = Path("samples/openwrt_mips_router.bin")
    assert sample_fw.exists()

    pipeline = FirmwareAnalysisPipeline()
    report = pipeline.run_full_analysis(sample_fw)

    # Validate Report Structure
    assert isinstance(report, FirmwareReport)
    assert report.metadata.filename == "openwrt_mips_router.bin"
    assert report.metadata.total_files > 0
    assert report.metadata.total_binaries >= 2

    # Validate Binary Hardening Matrix (Checksec)
    assert len(report.audit_matrix) >= 2
    httpd_matrix = next((b for b in report.audit_matrix if "httpd" in b.path), None)
    assert httpd_matrix is not None
    assert httpd_matrix.nx is False
    assert httpd_matrix.pie is False

    # Validate Vulnerability Findings (Appendix A conformity)
    assert len(report.vulnerabilities) > 0
    
    categories = [f.category for f in report.vulnerabilities]
    cwes = [f.cwe for f in report.vulnerabilities]

    assert Category.MEMORY_CORRUPTION in categories
    assert Category.HARDCODED_SECRET in categories
    assert "CWE-120" in cwes or "CWE-121" in cwes
    assert "CWE-78" in cwes

    # Validate Crash State on Memory Corruption Finding
    crash_findings = [f for f in report.vulnerabilities if f.crash_state is not None]
    assert len(crash_findings) >= 1
    assert crash_findings[0].crash_state.overflow_offset == 64
    assert crash_findings[0].crash_state.fault_address is not None

    # Validate 100% Secret Redaction
    secret_findings = [f for f in report.vulnerabilities if f.category == Category.HARDCODED_SECRET]
    assert len(secret_findings) >= 1
    for sf in secret_findings:
        assert sf.redacted is True
        assert "AKIAIOSFODNN7EXAMPLE" not in sf.evidence_ref

    # Validate Output Files Created
    report_file = settings.REPORT_DIR / f"{pipeline.firmware_id}_report.json"
    inv_file = settings.REPORT_DIR / f"{pipeline.firmware_id}_inventory.json"
    audit_log = settings.LOGS_DIR / f"{pipeline.firmware_id}_audit.jsonl"

    assert report_file.exists()
    assert inv_file.exists()
    assert audit_log.exists()
