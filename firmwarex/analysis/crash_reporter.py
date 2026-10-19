"""
Project Unit42-FirmwareX — Non-Weaponized Crash State Diagnostic Reporter
Captures crash registers and fault addresses for human verification without weaponization (PRD Part A & Appendix A).
"""

from typing import Dict, Any, Optional
from firmwarex.schema import CrashState

class CrashReporter:
    """Formats and validates diagnostic crash state for safety and verification"""

    @staticmethod
    def format_diagnostic_report(crash: CrashState, binary_name: str, arch: str) -> Dict[str, Any]:
        """Produces a clean diagnostic report for vulnerability researchers"""
        return {
            "target_binary": binary_name,
            "architecture": arch,
            "faulting_address": crash.fault_address,
            "overflow_offset_bytes": crash.overflow_offset,
            "stack_backtrace_hash": crash.stack_hash,
            "register_state": crash.registers,
            "weaponization_status": "NONE_DISALLOWED",
            "safety_classification": "DIAGNOSTIC_ONLY"
        }

    @staticmethod
    def assert_non_weaponized(finding_evidence: str, crash: Optional[CrashState]) -> bool:
        """Safety invariant: Verifies no shellcode, NOP sleds, or exploit strings exist in evidence"""
        banned_payload_indicators = [
            "\\x90\\x90\\x90", # NOP sled
            "/bin/sh",
            "payload_hex",
            "reverse_shell",
            "execve_shellcode"
        ]
        for indicator in banned_payload_indicators:
            if indicator in finding_evidence:
                return False
        return True
