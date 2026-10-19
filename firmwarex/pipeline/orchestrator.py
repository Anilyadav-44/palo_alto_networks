"""
Project Unit42-FirmwareX — Central Analysis Pipeline Orchestrator
Coordinates unpacker, audit, emulation, symbolic/taint, scanner, and report generation (PRD Week 4).
"""

import time
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
import uuid

from firmwarex.config import settings
from firmwarex.schema import (
    FirmwareMetadata, BinaryAuditRecord, VulnerabilityFinding, FirmwareReport,
    AnalysisJobStatus, AnalysisStage
)
from firmwarex.unpacker.extractor import FirmwareExtractor
from firmwarex.unpacker.tree import FileTreeGenerator
from firmwarex.audit.checksec import HardeningAuditor
from firmwarex.audit.dangerous_sinks import DangerousSinksScanner
from firmwarex.audit.elf_parser import ELFInspector
from firmwarex.emulation.sandbox import IsolatedSandbox
from firmwarex.emulation.qemu_runner import QEMUOrchestrator
from firmwarex.analysis.taint_tracker import TaintTracker
from firmwarex.analysis.symbolic_engine import BoundedSymbolicEngine
from firmwarex.analysis.cfg import CFGGenerator
from firmwarex.scanner.secret_scanner import SecretScanner
from firmwarex.scanner.crypto_scanner import CryptoScanner
from firmwarex.pipeline.normalizer import FindingNormalizer
from firmwarex.telemetry.tracer import AuditLogger, SpanTracer

class FirmwareAnalysisPipeline:
    """End-to-end orchestrator for firmware attack surface and vulnerability discovery"""

    def __init__(self, firmware_id: Optional[str] = None):
        self.firmware_id = firmware_id or str(uuid.uuid4())
        self.sandbox = IsolatedSandbox()
        self.qemu = QEMUOrchestrator(sandbox=self.sandbox)
        self.symbolic = BoundedSymbolicEngine()

    def run_full_analysis(
        self,
        firmware_path: Path,
        progress_callback: Optional[Callable[[AnalysisStage, int, str], None]] = None
    ) -> FirmwareReport:
        firmware_path = Path(firmware_path)
        
        def update_progress(stage: AnalysisStage, pct: int, msg: str):
            if progress_callback:
                progress_callback(stage, pct, msg)

        # Stage 1: Unpacking & Entropy Analysis
        update_progress(AnalysisStage.UNPACKING, 10, "Unpacking firmware container and calculating entropy...")
        with SpanTracer(self.firmware_id, "UNPACKING"):
            extractor = FirmwareExtractor(self.firmware_id, firmware_path)
            unpack_res = extractor.unpack()

        rootfs_dir = Path(unpack_res["output_directory"])

        # Stage 2: File-tree inventory & ELF discovery
        update_progress(AnalysisStage.STATIC_AUDIT, 25, "Building file inventory and discovering ELF executables...")
        inventory = FileTreeGenerator.generate_inventory(rootfs_dir)
        binary_paths = FileTreeGenerator.find_binaries(rootfs_dir)

        # Stage 3: Static Hardening Audit & Sinks
        update_progress(AnalysisStage.STATIC_AUDIT, 40, "Auditing exploit mitigations and dangerous functions...")
        audit_matrix: List[BinaryAuditRecord] = []
        all_findings: List[VulnerabilityFinding] = []
        
        with SpanTracer(self.firmware_id, "STATIC_AUDIT"):
            for b_path in binary_paths:
                rel_path = f"/{b_path.relative_to(rootfs_dir).as_posix()}"
                
                # Checksec audit
                record = HardeningAuditor.audit_binary(b_path, rootfs_rel_path=rel_path)
                audit_matrix.append(record)

                # Inspect ELF symbols
                elf_info = ELFInspector.inspect(b_path)
                
                # Scan dangerous sinks
                sink_findings = DangerousSinksScanner.scan_binary(
                    file_path=b_path,
                    firmware_id=self.firmware_id,
                    rootfs_rel_path=rel_path,
                    arch=record.architecture
                )
                all_findings.extend(sink_findings)

                # Scan weak crypto symbols
                crypto_findings = CryptoScanner.scan_binary_crypto(
                    firmware_id=self.firmware_id,
                    binary_rel_path=rel_path,
                    arch=record.architecture,
                    symbols=elf_info["imported_functions"] + elf_info["symbols"]
                )
                all_findings.extend(crypto_findings)

        # Stage 4: Cross-Architecture Emulation & Sandbox Verification
        update_progress(AnalysisStage.EMULATION, 55, "Emulating binaries under isolated sandbox with NVRAM stubs...")
        with SpanTracer(self.firmware_id, "EMULATION"):
            for b_path in binary_paths[:3]: # Priority emulation on top services
                rel_path = f"/{b_path.relative_to(rootfs_dir).as_posix()}"
                record_match = next((r for r in audit_matrix if r.path == rel_path), None)
                arch_str = record_match.architecture if record_match else "MIPS"
                endian_str = record_match.endianness if record_match else "big"

                # Run in isolated sandbox
                emu_res = self.qemu.execute_binary(
                    binary_path=b_path,
                    rootfs_dir=rootfs_dir,
                    arch=arch_str,
                    endianness=endian_str,
                    stdin_data=b"test_probe_data\n"
                )

        # Stage 5: Symbolic Execution & Taint Analysis
        update_progress(AnalysisStage.SYMBOLIC_TAINT, 75, "Tracing input-to-sink taint and solving path constraints...")
        with SpanTracer(self.firmware_id, "SYMBOLIC_TAINT"):
            for b_path in binary_paths[:3]:
                rel_path = f"/{b_path.relative_to(rootfs_dir).as_posix()}"
                record_match = next((r for r in audit_matrix if r.path == rel_path), None)
                arch_str = record_match.architecture if record_match else "MIPS"
                
                elf_info = ELFInspector.inspect(b_path)
                taint_findings = TaintTracker.analyze_binary_patterns(
                    firmware_id=self.firmware_id,
                    binary_rel_path=rel_path,
                    arch=arch_str,
                    imported_symbols=elf_info["imported_functions"]
                )
                all_findings.extend(taint_findings)

                # Read code for symbolic execution
                with open(b_path, "rb") as f:
                    code_sample = f.read(2048)

                symbolic_findings = self.symbolic.explore_function_paths(
                    firmware_id=self.firmware_id,
                    binary_rel_path=rel_path,
                    arch=arch_str,
                    function_name="main",
                    code_bytes=code_sample
                )
                all_findings.extend(symbolic_findings)

        # Stage 6: Hardcoded Secret & Credential Scanning
        update_progress(AnalysisStage.SECRET_SCAN, 90, "Scanning files for credentials, private keys, and API tokens...")
        with SpanTracer(self.firmware_id, "SECRET_SCAN"):
            secret_findings = SecretScanner.scan_directory(rootfs_dir, self.firmware_id)
            all_findings.extend(secret_findings)

        # Stage 7: Normalization & Report Generation
        update_progress(AnalysisStage.COMPLETED, 100, "Generating final CWE-classified security posture report...")
        with SpanTracer(self.firmware_id, "REPORT_NORMALIZATION"):
            metadata = FirmwareMetadata(
                firmware_id=self.firmware_id,
                filename=firmware_path.name,
                size_bytes=unpack_res["size_bytes"],
                sha256=unpack_res["sha256"],
                format_detected=unpack_res["format_detected"],
                entropy_mean=unpack_res["entropy"]["mean_entropy"],
                total_files=len(inventory),
                total_binaries=len(binary_paths)
            )

            report = FindingNormalizer.generate_report(
                metadata=metadata,
                audit_matrix=audit_matrix,
                raw_findings=all_findings
            )

            # Persist report JSON
            report_file = settings.REPORT_DIR / f"{self.firmware_id}_report.json"
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(report.model_dump_json(indent=2))

            # Persist inventory JSON
            inv_file = settings.REPORT_DIR / f"{self.firmware_id}_inventory.json"
            with open(inv_file, "w", encoding="utf-8") as f:
                f.write(json.dumps([node.model_dump() for node in inventory], indent=2))

            AuditLogger.log_event(
                firmware_id=self.firmware_id,
                stage="PIPELINE_COMPLETE",
                event_type="SUCCESS",
                details={
                    "total_findings": len(report.vulnerabilities),
                    "posture_score": report.overall_posture_score,
                    "report_path": str(report_file)
                }
            )

        return report
