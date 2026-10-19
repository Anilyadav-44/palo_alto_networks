"""
Unit Tests — Sandbox Isolation, Network Egress Deny & Quota Enforcement (PRD Week 2 & Section 7)
"""

import sys
import time
from pathlib import Path
from firmwarex.emulation.sandbox import IsolatedSandbox
from firmwarex.emulation.nvram_stub import NVRAMStubber

def test_egress_containment_proof():
    sandbox = IsolatedSandbox()
    proof = sandbox.verify_egress_containment()
    assert proof["egress_denied"] is True
    assert proof["containment_active"] is True
    assert proof["isolation_verified"] is True
    assert "127.0.0.1:9" in proof["proxy_guard"]

def test_sandbox_quota_timeout():
    # Configure sandbox with a short 1-second timeout
    sandbox = IsolatedSandbox(timeout_seconds=1)
    
    # Run a Python command that sleeps for 5 seconds
    cmd = [sys.executable, "-c", "import time; time.sleep(5)"]
    result = sandbox.run_process_with_quotas(cmd, cwd=Path("."))
    
    # Process must be terminated due to quota breach
    assert result["quota_breached"] is True
    assert "timeout" in result["breach_reason"].lower()
    assert result["returncode"] == -9

def test_nvram_stub_injection(tmp_path):
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    
    res = NVRAMStubber.apply_stubs(rootfs, custom_overrides={"http_username": "unit42_admin"})
    assert res["applied_keys_count"] > 10
    
    conf_file = rootfs / "etc/nvram.conf"
    assert conf_file.exists()
    content = conf_file.read_text()
    assert "http_username=unit42_admin" in content
    assert "lan_ipaddr=192.168.1.1" in content
