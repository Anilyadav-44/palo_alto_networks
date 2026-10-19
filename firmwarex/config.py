"""
Project Unit42-FirmwareX — Global Configuration & Containment Policies
Palo Alto Networks // Unit 42 Threat Research & Security Engineering
"""

import os
from pathlib import Path
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Unit42-FirmwareX"
    VERSION: str = "1.0.0"
    ORGANISATION: str = "Palo Alto Networks — Unit 42"
    CLASSIFICATION: str = "Internal // Confidential"

    # Base filesystem paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    STORAGE_DIR: Path = BASE_DIR / "data_storage"
    FIRMWARE_UPLOAD_DIR: Path = STORAGE_DIR / "uploads"
    EXTRACTION_DIR: Path = STORAGE_DIR / "extracted"
    REPORT_DIR: Path = STORAGE_DIR / "reports"
    LOGS_DIR: Path = STORAGE_DIR / "logs"

    # Sandboxing & Resource Quotas (Guardrails)
    SANDBOX_TIMEOUT_SECONDS: int = 120           # Max wall-clock time per dynamic analysis job
    MAX_MEMORY_BYTES: int = 512 * 1024 * 1024    # 512 MB memory limit
    MAX_CPU_PERCENT: float = 90.0                # CPU quota threshold
    MAX_FILE_EXTRACTION_COUNT: int = 5000        # Zip bomb / tar bomb prevention
    MAX_FIRMWARE_SIZE_BYTES: int = 250 * 1024 * 1024 # 250 MB max image size
    NETWORK_EGRESS_DENIED: bool = True           # Complete network isolation

    # Symbolic Execution Budgets (Mitigating Path Explosion)
    SYMBOLIC_MAX_DEPTH: int = 35                 # Bound search depth
    SYMBOLIC_MAX_PATHS: int = 50                 # Max paths to explore per function
    SYMBOLIC_TIMEOUT_SECONDS: int = 30           # 30 seconds max per function

    # API Settings
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000

    # Dashboard Settings
    DASHBOARD_PORT: int = 8501

    model_config = {
        "env_prefix": "FIRMWAREX_",
        "case_sensitive": False
    }

settings = Settings()

# Ensure directories exist safely
for path in [settings.STORAGE_DIR, settings.FIRMWARE_UPLOAD_DIR, settings.EXTRACTION_DIR, settings.REPORT_DIR, settings.LOGS_DIR]:
    path.mkdir(parents=True, exist_ok=True)
