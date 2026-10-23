"""
Unit Tests — Taint Tracking, Symbolic Execution & Non-Weaponization (PRD Week 3 & FR-1.5)
"""

from pathlib import Path
from firmwarex.analysis.taint_tracker import TaintTracker
from firmwarex.analysis.symbolic_engine import BoundedSymbolicEngine
from firmwarex.analysis.crash_reporter import CrashReporter
from firmwarex.analysis.cfg import CFGGenerator
from firmwarex.schema import Category, RiskRating

def test_taint_tracker_propagation():
    finding = TaintTracker.trace_dataflow(
        firmware_id="fw_123",
        binary_path="/bin/httpd",
        arch="MIPS",
        source_name="http_param",
        source_param="cmd_query",
        sink_name="system",
        call_addresses=["0x00401140", "0x00401188", "0x00401220"],
        reaching_condition="User input passed directly to system() without sanitization"
    )
    assert finding.cwe == "CWE-78"
    assert finding.category == Category.COMMAND_INJECTION
    assert finding.risk_rating == RiskRating.CRITICAL
    assert len(finding.tainted_path) == 3
    assert finding.address == "0x00401220"

def test_symbolic_engine_crash_state():
    engine = BoundedSymbolicEngine(max_depth=10, max_paths=20, timeout_seconds=5)
    
    # Dummy code bytes
    code = bytes.fromhex("27bdffe0 afbf001c 00000000 8fbf001c 03e00008 00000000")
    findings = engine.explore_function_paths(
        firmware_id="fw_123",
        binary_rel_path="/bin/httpd",
        arch="MIPS",
        function_name="process_request",
        code_bytes=code,
        entry_address=0x00401000
    )
    
    assert len(findings) >= 1
    f = findings[0]
    assert f.cwe == "CWE-121" # Stack overflow
    assert f.crash_state is not None
    assert f.crash_state.overflow_offset == 64
    assert f.crash_state.fault_address == "0x41414141"
    assert "ra" in f.crash_state.registers

def test_non_weaponization_guardrail():
    # Safe diagnostic report passes
    safe_evidence = "Discovered stack buffer overflow at offset 64. Register $ra overwritten."
    assert CrashReporter.assert_non_weaponized(safe_evidence, None) is True

    # Malicious weaponized exploit attempt is flagged and blocked
    exploit_attempt = "Injected shellcode: \\x90\\x90\\x90 /bin/sh"
    assert CrashReporter.assert_non_weaponized(exploit_attempt, None) is False

def test_cfg_generator():
    code = bytes.fromhex("55 89e5 83ec40 c9 c3") # x86 prologue/epilogue
    cfg = CFGGenerator.generate_cfg_from_code(
        code_bytes=code,
        entry_address=0x00401000,
        arch="x86",
        function_name="main",
        binary_path="/bin/busybox"
    )
    assert len(cfg.nodes) >= 1
    assert cfg.entry_address == "0x401000"

def test_protocol_fuzzer_mutations():
    from firmwarex.analysis.fuzzer import ProtocolFuzzer
    reqs = ProtocolFuzzer.generate_mutated_requests("/apply.cgi")
    assert len(reqs) >= 5
    assert any("overflow" == r["pattern_type"] for r in reqs)
    assert any("injection" == r["pattern_type"] for r in reqs)

    # Test UPnP and MQTT mutation generators (FR-4.1)
    upnp_cases = ProtocolFuzzer.generate_upnp_mutations()
    assert len(upnp_cases) >= 5
    assert any("SOAPAction" in c["headers"] for c in upnp_cases)

    mqtt_cases = ProtocolFuzzer.generate_mqtt_mutations()
    assert len(mqtt_cases) >= 5
    assert any(c["packet_type"] == "PUBLISH" for c in mqtt_cases)

    # Test fuzzer execution, crash detection, and stack hash deduplication (FR-4.2, FR-4.3)
    findings = ProtocolFuzzer.fuzz_service_target(
        firmware_id="fw_test_fuzz",
        binary_rel_path="/bin/httpd",
        protocol="HTTP",
        arch="MIPS"
    )
    assert len(findings) >= 1
    # Check deduplication: stack hashes must be unique
    stack_hashes = [f.crash_state.stack_hash for f in findings if f.crash_state]
    assert len(stack_hashes) == len(set(stack_hashes))
    assert all(f.category == Category.MEMORY_CORRUPTION for f in findings)
    assert all(f.confidence.value == "confirmed" for f in findings)
