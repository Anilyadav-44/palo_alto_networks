"""
Project Unit42-FirmwareX — Dangerous Sinks & Banned Functions Scanner
Audits ELF binaries for unsafe C standard library functions and command execution sinks (PRD FR-1.5).
"""

from pathlib import Path
from typing import List, Dict, Any, Tuple
import uuid
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from firmwarex.schema import (
    VulnerabilityFinding, Category, RiskRating, Confidence, Architecture
)

DANGEROUS_SINKS_MAP = {
    # Memory Corruption - Buffer Copy without Checking Size (CWE-120)
    "strcpy": {"cwe": "CWE-120", "category": Category.MEMORY_CORRUPTION, "risk": RiskRating.HIGH, "desc": "Unbounded string copy sink"},
    "strcat": {"cwe": "CWE-120", "category": Category.MEMORY_CORRUPTION, "risk": RiskRating.MEDIUM, "desc": "Unbounded string concatenation sink"},
    "gets": {"cwe": "CWE-120", "category": Category.MEMORY_CORRUPTION, "risk": RiskRating.CRITICAL, "desc": "Inherently insecure gets() function"},
    
    # Format String (CWE-134)
    "sprintf": {"cwe": "CWE-134", "category": Category.MEMORY_CORRUPTION, "risk": RiskRating.HIGH, "desc": "Unchecked string format sink without buffer limit"},
    "vsprintf": {"cwe": "CWE-134", "category": Category.MEMORY_CORRUPTION, "risk": RiskRating.HIGH, "desc": "Variable argument format string sink without bounds"},
    
    # OS Command Injection (CWE-78)
    "system": {"cwe": "CWE-78", "category": Category.COMMAND_INJECTION, "risk": RiskRating.CRITICAL, "desc": "OS command execution via shell interpreter"},
    "popen": {"cwe": "CWE-78", "category": Category.COMMAND_INJECTION, "risk": RiskRating.HIGH, "desc": "Command execution with pipe stream creation"},
    "execl": {"cwe": "CWE-78", "category": Category.COMMAND_INJECTION, "risk": RiskRating.HIGH, "desc": "Direct process execution sink"},
    "execve": {"cwe": "CWE-78", "category": Category.COMMAND_INJECTION, "risk": RiskRating.HIGH, "desc": "Direct process execution sink"},
    
    # Out of Bounds Write / Memory Manipulation (CWE-787)
    "memcpy": {"cwe": "CWE-787", "category": Category.MEMORY_CORRUPTION, "risk": RiskRating.MEDIUM, "desc": "Raw memory copy sink"},
    "memmove": {"cwe": "CWE-787", "category": Category.MEMORY_CORRUPTION, "risk": RiskRating.LOW, "desc": "Raw memory move sink"}
}

class DangerousSinksScanner:
    """Scans ELF symbol tables and import tables for risky memory and command sinks"""

    @classmethod
    def scan_binary(cls, file_path: Path, firmware_id: str, rootfs_rel_path: str, arch: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        
        # Map arch string to Architecture Enum
        architecture_enum = Architecture.UNKNOWN
        for a in Architecture:
            if a.value.lower() == arch.lower():
                architecture_enum = a
                break

        found_sinks = set()
        
        try:
            with open(file_path, "rb") as f:
                if f.read(4) != b"\x7fELF":
                    return findings
                f.seek(0)
                elffile = ELFFile(f)
                
                # Iterate symbols across all symbol sections
                for section in elffile.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        for sym in section.iter_symbols():
                            name = sym.name
                            if name in DANGEROUS_SINKS_MAP:
                                found_sinks.add((name, hex(sym['st_value']) if sym['st_value'] else None))

            for sink_name, addr in found_sinks:
                sink_info = DANGEROUS_SINKS_MAP[sink_name]
                finding = VulnerabilityFinding(
                    vulnerability_id=str(uuid.uuid4()),
                    firmware_id=firmware_id,
                    binary=rootfs_rel_path,
                    architecture=architecture_enum,
                    category=sink_info["category"],
                    cwe=sink_info["cwe"],
                    address=addr,
                    sink=sink_name,
                    source="statically_linked_import",
                    tainted_path=[],
                    crash_state=None,
                    risk_rating=sink_info["risk"],
                    confidence=Confidence.HEURISTIC,
                    evidence_ref=f"Detected banned C runtime API call: {sink_name}() [{sink_info['desc']}]",
                    redacted=False
                )
                findings.append(finding)

        except Exception:
            pass

        return findings
