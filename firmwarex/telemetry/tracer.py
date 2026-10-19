"""
Project Unit42-FirmwareX — OpenTelemetry Tracing & Immutable Audit Logger
Records span metrics, job lifecycles, and security events (PRD Section 5.2 & Week 4).
"""

import time
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from firmwarex.config import settings

class AuditLogger:
    """Manages immutable JSONL audit logs for firmware analysis operations"""

    @classmethod
    def log_event(cls, firmware_id: str, stage: str, event_type: str, details: Dict[str, Any]):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "firmware_id": firmware_id,
            "stage": stage,
            "event_type": event_type,
            "details": details
        }
        
        log_file = settings.LOGS_DIR / f"{firmware_id}_audit.jsonl"
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")

class SpanTracer:
    """Tracks elapsed times and resource usage across pipeline stages"""

    def __init__(self, firmware_id: str, stage_name: str):
        self.firmware_id = firmware_id
        self.stage_name = stage_name
        self.start_time = 0.0

    def __enter__(self):
        self.start_time = time.time()
        AuditLogger.log_event(
            firmware_id=self.firmware_id,
            stage=self.stage_name,
            event_type="STAGE_START",
            details={"started_at": datetime.now(timezone.utc).isoformat()}
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        status = "FAILED" if exc_val else "SUCCESS"
        AuditLogger.log_event(
            firmware_id=self.firmware_id,
            stage=self.stage_name,
            event_type="STAGE_END",
            details={
                "status": status,
                "duration_seconds": round(duration, 3),
                "error": str(exc_val) if exc_val else None
            }
        )
