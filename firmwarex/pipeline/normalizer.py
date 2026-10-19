"""
Project Unit42-FirmwareX — Report Normalizer & Posture Evaluator
Normalizes findings into Appendix A JSON schema and computes aggregate firmware posture score.
"""

from typing import List, Dict, Any, Tuple
from firmwarex.schema import (
    VulnerabilityFinding, BinaryAuditRecord, FirmwareMetadata, FirmwareReport,
    RiskRating, Category
)

class FindingNormalizer:
    """Consolidates findings from all analysis stages, removes duplicates, and scores posture"""

    @classmethod
    def deduplicate_findings(cls, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        seen = set()
        deduped = []
        for f in findings:
            key = (f.binary, f.cwe, f.address or "", f.sink or "", f.source or "")
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    @classmethod
    def compute_posture_score(
        cls,
        audit_matrix: List[BinaryAuditRecord],
        findings: List[VulnerabilityFinding]
    ) -> float:
        """
        Computes firmware posture score from 0.0 (severely vulnerable) to 100.0 (hardened).
        Deducts points for vulnerabilities and missing mitigations across binaries.
        """
        score = 100.0

        # Vulnerability penalties
        for f in findings:
            if f.risk_rating == RiskRating.CRITICAL:
                score -= 15.0
            elif f.risk_rating == RiskRating.HIGH:
                score -= 8.0
            elif f.risk_rating == RiskRating.MEDIUM:
                score -= 4.0
            elif f.risk_rating == RiskRating.LOW:
                score -= 1.0

        # Hardening matrix penalties (average across executables)
        if audit_matrix:
            total_hardening_penalties = 0.0
            for record in audit_matrix:
                pen = 0.0
                if not record.nx:
                    pen += 5.0
                if not record.pie:
                    pen += 4.0
                if record.relro == "none":
                    pen += 4.0
                elif record.relro == "partial":
                    pen += 2.0
                if not record.stack_canary:
                    pen += 5.0
                total_hardening_penalties += pen
            
            avg_hardening_penalty = total_hardening_penalties / len(audit_matrix)
            score -= avg_hardening_penalty

        return round(max(0.0, min(100.0, score)), 1)

    @classmethod
    def generate_report(
        cls,
        metadata: FirmwareMetadata,
        audit_matrix: List[BinaryAuditRecord],
        raw_findings: List[VulnerabilityFinding]
    ) -> FirmwareReport:
        deduped = cls.deduplicate_findings(raw_findings)
        posture_score = cls.compute_posture_score(audit_matrix, deduped)

        secret_count = sum(1 for f in deduped if f.category == Category.HARDCODED_SECRET)
        memory_count = sum(1 for f in deduped if f.category == Category.MEMORY_CORRUPTION)
        cmd_count = sum(1 for f in deduped if f.category == Category.COMMAND_INJECTION)
        crypto_count = sum(1 for f in deduped if f.category == Category.WEAK_CRYPTO)

        # Risk distribution
        risk_dist = {
            "critical": sum(1 for f in deduped if f.risk_rating == RiskRating.CRITICAL),
            "high": sum(1 for f in deduped if f.risk_rating == RiskRating.HIGH),
            "medium": sum(1 for f in deduped if f.risk_rating == RiskRating.MEDIUM),
            "low": sum(1 for f in deduped if f.risk_rating == RiskRating.LOW),
            "info": sum(1 for f in deduped if f.risk_rating == RiskRating.INFO)
        }

        # CWE breakdown
        cwe_dist = {}
        for f in deduped:
            cwe_dist[f.cwe] = cwe_dist.get(f.cwe, 0) + 1

        summary = {
            "total_findings": len(deduped),
            "risk_distribution": risk_dist,
            "cwe_distribution": cwe_dist,
            "category_counts": {
                "memory_corruption": memory_count,
                "command_injection": cmd_count,
                "hardcoded_secret": secret_count,
                "weak_crypto": crypto_count
            },
            "binaries_audited": len(audit_matrix),
            "posture_score": posture_score
        }

        return FirmwareReport(
            metadata=metadata,
            audit_matrix=audit_matrix,
            vulnerabilities=deduped,
            secret_findings_count=secret_count,
            memory_findings_count=memory_count,
            overall_posture_score=posture_score,
            summary=summary
        )
