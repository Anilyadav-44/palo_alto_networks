"""
Unit Tests — Unpacker, Signatures, Entropy & Quotas (PRD Week 1 & FR-1.1, FR-1.2)
"""

import pytest
from pathlib import Path
from firmwarex.unpacker.detector import FirmwareDetector
from firmwarex.unpacker.entropy import EntropyAnalyzer
from firmwarex.unpacker.extractor import FirmwareExtractor, UnpackerQuotaExceeded
from firmwarex.unpacker.tree import FileTreeGenerator
from firmwarex.config import settings

def test_signature_detection():
    # Test uImage header detection
    data = b"\x27\x05\x19\x56" + (b"\x00" * 60)
    matches = FirmwareDetector.scan_signatures(data)
    assert any(m["name"] == "U-Boot uImage" for m in matches)
    assert "uImage" in FirmwareDetector.detect_primary_container(data)

def test_entropy_analyzer():
    # Low entropy (uniform zeros)
    zeros = b"\x00" * 1024
    e_low = EntropyAnalyzer.calculate_block_entropy(zeros)
    assert e_low == 0.0

    # High entropy (pseudorandom bytes)
    import os
    rand_data = os.urandom(2048)
    e_high = EntropyAnalyzer.calculate_block_entropy(rand_data)
    assert e_high > 7.0

    curve = EntropyAnalyzer.analyze(rand_data)
    assert curve["max_entropy"] > 7.0
    assert len(curve["data_points"]) > 0

def test_extractor_sample_firmware():
    sample_fw = Path("samples/openwrt_mips_router.bin")
    assert sample_fw.exists()

    extractor = FirmwareExtractor("test_fw_001", sample_fw)
    result = extractor.unpack()
    assert result["success"] is True
    assert result["files_extracted"] > 0
    assert Path(result["output_directory"]).exists()

def test_file_tree_inventory():
    extracted_dir = settings.EXTRACTION_DIR / "test_fw_001"
    assert extracted_dir.exists()

    inventory = FileTreeGenerator.generate_inventory(extracted_dir)
    assert len(inventory) > 0
    paths = [n.path for n in inventory]
    assert any("bin/httpd" in p for p in paths)

    binaries = FileTreeGenerator.find_binaries(extracted_dir)
    assert len(binaries) >= 1
