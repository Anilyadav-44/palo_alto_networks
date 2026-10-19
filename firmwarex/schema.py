"""
Project Unit42-FirmwareX — Data Architecture & Finding Schema
Strictly conforms to PRD Section 5.3 & Appendix A.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field

class Architecture(str, Enum):
    ARM32 = "ARM32"
    ARM64 = "ARM64"
    MIPS = "MIPS"
    MIPSEL = "MIPSEL"
    X86 = "x86"
    X86_64 = "x86_64"
    UNKNOWN = "UNKNOWN"

class Category(str, Enum):
    MEMORY_CORRUPTION = "memory_corruption"
    HARDCODED_SECRET = "hardcoded_secret"
    WEAK_CRYPTO = "weak_crypto"
    MISSING_MITIGATION = "missing_mitigation"
    COMMAND_INJECTION = "command_injection"

class RiskRating(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    HEURISTIC = "heuristic"

class FindingStatus(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    VALIDATED = "validated"
    FALSE_POSITIVE = "false_positive"

class RelroStatus(str, Enum):
    NONE = "none"
    PARTIAL = "partial"
    FULL = "full"

class CrashState(BaseModel):
    fault_address: Optional[str] = Field(None, description="Hex address of fault e.g., 0x00401a2c")
    registers: Optional[Dict[str, str]] = Field(None, description="Diagnostic snapshot of CPU registers")
    overflow_offset: Optional[int] = Field(None, description="Discovered buffer overflow offset in bytes")
    stack_hash: Optional[str] = Field(None, description="Unique hash of stack backtrace for dedup")

class VulnerabilityFinding(BaseModel):
    """Normalized finding conforming strictly to Appendix A"""
    vulnerability_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    firmware_id: str
    binary: str = Field(description="Path within reconstructed rootfs")
    architecture: Architecture = Architecture.UNKNOWN
    category: Category
    cwe: str = Field(description="CWE classification e.g., CWE-120")
    address: Optional[str] = Field(None, description="Hex virtual address e.g. 0x00401a2c")
    sink: Optional[str] = Field(None, description="Dangerous sink symbol e.g., strcpy, system, popen")
    source: Optional[str] = Field(None, description="Input origin e.g. http_param:host, nvram:pass")
    tainted_path: List[str] = Field(default_factory=list, description="Array of hex addresses along trace")
    crash_state: Optional[CrashState] = None
    risk_rating: RiskRating
    confidence: Confidence
    evidence_ref: str = Field(description="Redacted evidence / artefact reference")
    redacted: bool = True
    status: FindingStatus = FindingStatus.NEW
    detected_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class BinaryAuditRecord(BaseModel):
    """Mitigation matrix record per ELF binary (PRD Section 8.1)"""
    path: str
    architecture: str
    endianness: str
    bits: int
    nx: bool
    pie: bool
    relro: str
    stack_canary: bool
    fortify: bool
    stripped: bool
    sha256: Optional[str] = None
    banned_calls_count: int = 0
    risk_score: float = 0.0

class FileSystemNode(BaseModel):
    """File inventory entry (PRD FR-1.2)"""
    path: str
    name: str
    type: str  # file, directory, symlink, block, fifo
    size_bytes: int
    sha256: Optional[str] = None
    mime_type: Optional[str] = None
    permissions: Optional[str] = None
    is_executable: bool = False

class FirmwareMetadata(BaseModel):
    firmware_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    filename: str
    size_bytes: int
    sha256: str
    format_detected: str
    entropy_mean: float
    total_files: int = 0
    total_binaries: int = 0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class AnalysisStage(str, Enum):
    PENDING = "pending"
    UNPACKING = "unpacking"
    STATIC_AUDIT = "static_audit"
    EMULATION = "emulation"
    SYMBOLIC_TAINT = "symbolic_taint"
    SECRET_SCAN = "secret_scan"
    COMPLETED = "completed"
    FAILED = "failed"

class AnalysisJobStatus(BaseModel):
    job_id: str
    firmware_id: str
    stage: AnalysisStage
    progress_percentage: int
    message: str
    error: Optional[str] = None
    started_at: str
    updated_at: str
    completed_at: Optional[str] = None

class CFGNode(BaseModel):
    id: str
    address: str
    name: Optional[str] = None
    instructions: List[str] = Field(default_factory=list)
    is_sink: bool = False
    is_source: bool = False
    is_tainted: bool = False

class CFGEdge(BaseModel):
    source: str
    target: str
    type: str = "normal"  # normal, conditional_true, conditional_false, call, return

class CFGData(BaseModel):
    binary_path: str
    function_name: str
    entry_address: str
    nodes: List[CFGNode] = Field(default_factory=list)
    edges: List[CFGEdge] = Field(default_factory=list)

class FirmwareReport(BaseModel):
    metadata: FirmwareMetadata
    audit_matrix: List[BinaryAuditRecord]
    vulnerabilities: List[VulnerabilityFinding]
    secret_findings_count: int
    memory_findings_count: int
    overall_posture_score: float  # 0 to 100 (100 = best, 0 = worst)
    summary: Dict[str, Any]
