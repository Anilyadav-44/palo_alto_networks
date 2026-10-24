"""
Pytest configuration and session-wide fixtures for Unit42-FirmwareX.
Ensures that all test fixtures, extracted sample firmware, and baseline reports
exist before any test runs, guaranteeing deterministic test execution across any CI runner.
"""

import pytest
from pathlib import Path

from firmwarex.config import settings
from firmwarex.unpacker.extractor import FirmwareExtractor
from firmwarex.pipeline.orchestrator import FirmwareAnalysisPipeline

@pytest.fixture(scope="session", autouse=True)
def setup_test_fixtures():
    """
    Session-level fixture that automatically prepares the test firmware fixtures
    and unpacks 'test_fw_001' before any individual test module executes.
    """
    # 1. Ensure storage directories exist
    for p in [settings.STORAGE_DIR, settings.FIRMWARE_UPLOAD_DIR, settings.EXTRACTION_DIR, settings.REPORT_DIR, settings.LOGS_DIR]:
        p.mkdir(parents=True, exist_ok=True)

    # 2. Ensure sample firmware exists
    sample_fw = Path("samples/openwrt_mips_router.bin")
    if not sample_fw.exists():
        from samples.generator import build_synthetic_firmware
        build_synthetic_firmware()

    # 3. Unpack test_fw_001 so test_audit, test_scanner, and test_unpacker always succeed
    target_dir = settings.EXTRACTION_DIR / "test_fw_001"
    if not target_dir.exists() or not (target_dir / "bin/httpd").exists():
        extractor = FirmwareExtractor("test_fw_001", sample_fw)
        extractor.unpack()

    # 4. Generate at least one report so test_api has report data available
    existing_reports = list(settings.REPORT_DIR.glob("*_report.json"))
    if not existing_reports:
        pipeline = FirmwareAnalysisPipeline(firmware_id="test_fw_001")
        pipeline.run_full_analysis(sample_fw)

    yield
