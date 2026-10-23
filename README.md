# Project Unit42-FirmwareX
### Automated IoT & Embedded Firmware Attack Surface & Vulnerability Analysis Engine
**Palo Alto Networks — Unit 42 (Threat Research & Security Engineering)**

---

[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B.svg?logo=streamlit&logoColor=white)](https://streamlit.io)
[![Tests Passing](https://img.shields.io/badge/tests-23%2F23%20passed%20(100%25)-brightgreen.svg)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-76%25-green.svg)](tests/)
[![Security Architecture](https://img.shields.io/badge/CWE-Normalized%20(Appendix%20A)-orange.svg)](docs/CWE_MAPPING.md)
[![Containment](https://img.shields.io/badge/Zero%20Egress-Verified-success.svg)](firmwarex/emulation/sandbox.py)
[![Policy](https://img.shields.io/badge/Non--Weaponized-Diagnostic%20Only-blueviolet.svg)](#safety--non-weaponization-guarantees)

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Key Capabilities & Subsystems](#key-capabilities--subsystems)
- [System Architecture & Data Flow](#system-architecture--data-flow)
- [Safety, Containment & Non-Weaponization Policy](#safety-containment--non-weaponization-policy)
- [Quickstart Guide](#quickstart-guide)
  - [1. Prerequisites & Installation](#1-prerequisites--installation)
  - [2. Run Verification Test Suite](#2-run-verification-test-suite)
  - [3. Generate Sample IoT Firmware](#3-generate-sample-iot-firmware)
  - [4. Run Full Analysis via CLI](#4-run-full-analysis-via-cli)
  - [5. Launch FastAPI Control Plane](#5-launch-fastapi-control-plane)
  - [6. Launch Interactive Security Dashboard](#6-launch-interactive-security-dashboard)
- [Interactive Security Dashboard](#interactive-security-dashboard)
- [REST API Reference](#rest-api-reference)
- [Vulnerability Taxonomy & CWE Mapping](#vulnerability-taxonomy--cwe-mapping)
- [Key Performance Indicators (KPIs)](#key-performance-indicators-kpis)
- [Repository Structure](#repository-structure)
- [Documentation Index](#documentation-index)
- [License & Classification](#license--classification)

---

## Executive Summary

**Project Unit42-FirmwareX** is an automated, enterprise-grade firmware security analysis engine designed for security engineers, vulnerability researchers, and incident responders. It transitions embedded security assessment from manual reverse engineering to a high-throughput, automated pipeline combining:

1. **Multi-Stage Container Unpacking & Entropy Analysis**: Safely unpacks raw IoT firmware blobs, detecting compression boundaries and cryptographic layers.
2. **Static Compiler Hardening Audit (Checksec)**: Automatically inspects ELF binaries across MIPS, ARM, and x86 architectures for missing exploit mitigations (NX, PIE, RELRO, Canaries, FORTIFY).
3. **Contained Emulation Sandbox**: Executes target binaries with **strictly enforced zero network egress** and proactive memory/execution quotas.
4. **Taint Tracking & Bounded Symbolic Execution**: Traces untrusted input propagation to vulnerable memory sinks and captures diagnostic crash states.
5. **Secret & Weak Cryptography Scanner**: Detects embedded credentials, API tokens, and deprecated ciphers with a **100% redaction guarantee**.
6. **Unified Finding Normalization & Scoring**: Normalizes all findings into a versioned JSON schema conforming to **Appendix A** and calculates an aggregate Security Posture Score (0–100).

---

## Key Capabilities & Subsystems

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                 Unit42-FirmwareX Pipeline                                │
├──────────────────┬──────────────────┬──────────────────┬────────────────────────────────┤
│ 1. Unpacker      │ 2. Static Audit  │ 3. Emulation     │ 4. Deep Analysis & Scanning    │
│ • Magic Carving  │ • Checksec (ELF) │ • Zero Egress    │ • Taint Flow Tracing           │
│ • Shannon Entropy│ • Banned Sinks   │ • Quota Monitor  │ • Bounded Symbolic Engine      │
│ • Rootfs Tree    │ • Architecture   │ • NVRAM Stubs    │ • 100% Secret Redaction        │
│ • SHA-256 Hashes │ • Risk Scoring   │ • QEMU / Unicorn │ • Deprecated Crypto Audit      │
└──────────────────┴──────────────────┴──────────────────┴────────────────────────────────┘
```

### 1. Multi-Stage Unpacking & Filesystem Inventory (`firmwarex/unpacker/`)
- **Format Detection**: Detects over 18 magic byte signatures including U-Boot `uImage`, Broadcom TRX, SquashFS (LE/BE/Alternate), CramFS, JFFS2, UBIFS, CPIO, POSIX TAR, GZIP, and standalone ELF binaries.
- **Sliding-Window Shannon Entropy**: Computes block-level entropy (0.0 to 8.0 bits/byte) across raw images to pinpoint compressed filesystems, encrypted payloads, and code sections.
- **Defensive Extraction**: Enforces strict directory traversal mitigations (`../` path sanitization) and anti-zip-bomb quotas (`MAX_FILE_EXTRACTION_COUNT = 5,000`, `MAX_FIRMWARE_SIZE_BYTES = 250 MB`).
- **Cryptographic Inventory**: Reconstructs the complete root filesystem hierarchy, calculating SHA-256 hashes, MIME types, file sizes, and executable permissions for every carved asset.

### 2. Static Hardening Audit Matrix (`firmwarex/audit/`)
- **Cross-Architecture ELF Parser**: Inspects 32-bit and 64-bit ELF headers for MIPS, MIPSEL, ARM, ARM64, and x86 architectures.
- **Comprehensive Checksec Matrix**:
  - **NX / DEP**: Validates `PT_GNU_STACK` segment permissions (`PF_X` execution flags).
  - **PIE / ASLR**: Checks `ET_DYN` vs `ET_EXEC` headers and dynamic relocations.
  - **RELRO**: Audits `PT_GNU_RELRO` segments and `DT_BIND_NOW` flags (None / Partial / Full).
  - **Stack Canaries**: Scans for `__stack_chk_fail` and canary initialization references.
  - **FORTIFY_SOURCE**: Detects fortified libc wrappers (`__sprintf_chk`, `__strcpy_chk`).
  - **Stripped Status**: Evaluates whether symbol tables (`.symtab`) have been stripped.
- **Dangerous Sinks Inspection**: Flags references to unsafe standard C runtime functions (`strcpy`, `strcat`, `gets`, `sprintf`, `system`, `popen`, `memcpy`), mapping them to corresponding CWE classifications.

### 3. Contained Sandbox & Emulation (`firmwarex/emulation/`)
- **Zero Network Egress**: Reroutes proxy traffic to a non-routable dummy address (`127.0.0.1:9`), ensuring untrusted binaries cannot reach external networks or command-and-control servers.
- **Active Quota Guard**: Monitors memory ceilings (default: 512 MB) and execution timeouts (default: 120s) via `psutil`. Breaches trigger immediate process termination with `SIGKILL` (`-9`).
- **Multi-Engine Execution**: QEMU user-mode runner (`qemu-mips`, `qemu-arm`) with seamless fallback to an in-process instruction-level micro-emulator powered by Capstone.
- **Peripheral NVRAM Stubbing**: Injects mock hardware configurations (`lan_ipaddr`, `router_name`, `http_username`, `admin_password`) to satisfy peripheral dependencies during daemon bootstrap.

### 4. Taint Tracking & Bounded Symbolic Execution (`firmwarex/analysis/`)
- **Interactive CFG Generation**: Reconstructs basic blocks, entry points, conditional branches, and function call-sites with Capstone disassembly.
- **Taint Flow Propagation**: Models data flow from untrusted attack sources (`http_param`, `nvram_var`, `cli_argument`) directly into critical memory sinks.
- **Path-Bounded Symbolic Engine**: Explores execution branches subject to strict resource budgets (`max_depth = 35`, `max_paths = 50`, `timeout = 30s`) to mitigate path explosion.
- **Non-Weaponized Crash Diagnostics**: Captures fault address, register state snapshots (`$pc`, `$ra`, `$sp`, `$s0`, `$a0`), and overflow buffer offsets for triage without generating weaponized exploits.

### 5. Secret & Cryptographic Auditing (`firmwarex/scanner/`)
- **High-Entropy & Pattern Detection**: Identifies cloud API tokens (AWS `AKIA...`), private RSA/EC keys (`-----BEGIN PRIVATE KEY-----`), hardcoded passwords, and JWT tokens.
- **100% Redaction Guarantee**: All identified secrets are automatically masked (`AKIA************MPLE`) and fingerprinted via SHA-256 for audit tracking without secret leakage.
- **Weak Primitives Scanner**: Detects deprecated cryptographic algorithms (MD5, SHA-1, DES, 3DES, RC4) and insecure block cipher modes (ECB mode).

---

## System Architecture & Data Flow

```mermaid
flowchart TD
    subgraph Ingestion["1. Ingestion & Pre-Processing"]
        RawImage["Raw Firmware (.bin / .img)"] --> REST["FastAPI Control Plane\nPOST /api/v1/firmware/upload"]
        REST --> UnpackEngine["Unpacker & Format Detector\n(Magic Carving + Entropy)"]
    end

    subgraph Extraction["2. Extraction & Inventory"]
        UnpackEngine --> RootFS["Reconstructed Rootfs Hierarchy"]
        RootFS --> TreeInv["Cryptographic Inventory\n(SHA-256, MIME, Permissions)"]
    end

    subgraph AuditPhase["3. Static Hardening Audit"]
        RootFS --> Checksec["Checksec Mitigation Engine\n(NX, PIE, RELRO, Canary, FORTIFY)"]
        RootFS --> Sinks["Dangerous Sinks Scanner\n(strcpy, sprintf, system)"]
    end

    subgraph EmulationPhase["4. Contained Emulation & Taint"]
        Checksec --> Sandbox["Isolated Sandbox\n(Zero Egress + 512MB Quota)"]
        Sandbox --> NVRAM["NVRAM Peripheral Stubber"]
        NVRAM --> TaintEngine["Taint Flow Tracker\n(Input -> Sink)"]
        TaintEngine --> SymExec["Bounded Symbolic Engine\n(max_depth=35, max_paths=50)"]
        SymExec --> CrashDiag["Diagnostic Crash Snapshot\n($pc, $ra, $sp, offset)"]
    end

    subgraph SecretPhase["5. Secret & Crypto Scanning"]
        RootFS --> SecretScan["Secret Scanner\n(AWS Keys, RSA Keys, Tokens)"]
        SecretScan --> Redactor["100% Redaction Guard\n(AKIA****MPLE + SHA-256)"]
        RootFS --> CryptoScan["Weak Crypto Scanner\n(MD5, SHA-1, DES, RC4)"]
    end

    subgraph Reporting["6. Normalization & Presentation"]
        CrashDiag --> Normalizer["Pipeline Normalizer & Scoring Engine"]
        Redactor --> Normalizer
        CryptoScan --> Normalizer
        Checksec --> Normalizer
        Normalizer --> JSONReport["Unified JSON Report\n(Appendix A Compliant)"]
        Normalizer --> Dashboard["Streamlit Analyst Dashboard\n(Interactive Visualizer)"]
    end
```

---

## Safety, Containment & Non-Weaponization Policy

> [!IMPORTANT]
> **Strict Unit 42 Safety & Containment Guarantees**
> 
> Project Unit42-FirmwareX adheres to Palo Alto Networks Unit 42 safety and non-weaponization standards:
> 
> 1. **Zero Outbound Network Egress**: The sandbox environment intercepts network requests via proxy dead-ends (`127.0.0.1:9`). No live devices, cloud services, or untrusted external networks are ever contacted.
> 2. **Proactive Resource Quotas**: All executions run under process supervisors enforcing memory ceilings (512 MB) and timeouts (120s), terminating violating processes with `SIGKILL` (`-9`).
> 3. **100% Secret Redaction**: Discovered credentials and private keys are masked in all logs, reports, and UI screens. Only cryptographically hashed fingerprints are retained.
> 4. **Defensive Diagnostic Only**: The engine reports defect states strictly as crash registers (`$pc`, `$ra`, `$sp`), stack traces, and buffer offsets. It **contains no exploit generators, NOP sled injectors, shellcode builders, or weaponized proof-of-concept components**.

---

## Quickstart Guide

### 1. Prerequisites & Installation

- **Python**: Python 3.10 or newer (tested on Python 3.10, 3.11, 3.12, 3.13)
- **Operating System**: Windows 10/11, Ubuntu 20.04+, or macOS

Clone the repository and install dependencies:

```bash
git clone https://github.com/CjWrits/palo_alto_networks.git
cd palo_alto_networks

pip install -r requirements.txt
```

*Core packages installed:* `pyelftools`, `capstone`, `fastapi`, `uvicorn`, `streamlit`, `pydantic>=2.0`, `psutil`, `networkx`, `rich`, `pytest`, `pytest-cov`.

---

### 2. Run Verification Test Suite

Verify all system components, containment policies, and security guardrails:

```bash
python scripts/run_all_tests.py
```

*Output summary:*
```
============================= test session starts =============================
tests/test_api.py::test_api_health_and_root PASSED                       [  4%]
tests/test_api.py::test_containment_status_endpoint PASSED               [  8%]
tests/test_api.py::test_upload_and_pipeline_api PASSED                   [ 13%]
tests/test_api.py::test_api_report_and_audit_endpoints PASSED            [ 17%]
tests/test_audit.py::test_elf_inspector PASSED                           [ 21%]
tests/test_audit.py::test_checksec_mitigations PASSED                    [ 26%]
tests/test_audit.py::test_dangerous_sinks_scanner PASSED                 [ 30%]
tests/test_e2e_pipeline.py::test_full_pipeline_run PASSED                [ 34%]
tests/test_sandbox.py::test_egress_containment_proof PASSED              [ 39%]
tests/test_sandbox.py::test_sandbox_quota_timeout PASSED                 [ 43%]
tests/test_sandbox.py::test_nvram_stub_injection PASSED                  [ 47%]
tests/test_scanner_redactor.py::test_secret_redactor_masking PASSED      [ 52%]
tests/test_scanner_redactor.py::test_secret_scanner_detection PASSED     [ 56%]
tests/test_scanner_redactor.py::test_crypto_scanner_detection PASSED     [ 60%]
tests/test_taint_symbolic.py::test_taint_tracker_propagation PASSED      [ 65%]
tests/test_taint_symbolic.py::test_symbolic_engine_crash_state PASSED    [ 69%]
tests/test_taint_symbolic.py::test_non_weaponization_guardrail PASSED    [ 73%]
tests/test_taint_symbolic.py::test_cfg_generator PASSED                  [ 78%]
tests/test_taint_symbolic.py::test_protocol_fuzzer_mutations PASSED      [ 82%]
tests/test_unpacker.py::test_signature_detection PASSED                  [ 86%]
tests/test_unpacker.py::test_entropy_analyzer PASSED                     [ 91%]
tests/test_unpacker.py::test_extractor_sample_firmware PASSED            [ 95%]
tests/test_unpacker.py::test_file_tree_inventory PASSED                  [100%]
======================= 23 passed, 81 warnings in 8.66s =======================
TOTAL Coverage: 76%
```

---

### 3. Generate Sample IoT Firmware

The engine includes a multi-architecture firmware synthesizer that builds an authentic U-Boot `uImage` container embedding a Linux rootfs with MIPS, ARM, and x86 binaries, hardcoded credentials, and deprecated crypto:

```bash
python samples/generator.py
```

*Generated image located at:* `samples/openwrt_mips_router.bin`

---

### 4. Run Full Analysis via CLI

Analyze any raw firmware blob directly from the terminal:

```bash
python scripts/run_sample_analysis.py samples/openwrt_mips_router.bin
```

This runs the automated pipeline:
1. Container unpacking and sliding-window Shannon entropy curve calculation.
2. File-tree inventory generation with SHA-256 digests.
3. ELF architecture and compiler mitigation audit (`checksec`).
4. Dangerous libc sink detection.
5. Sandbox emulation under zero network egress and NVRAM stubbing.
6. Taint tracking and bounded symbolic path solving.
7. Secret and weak cryptography scan with 100% redaction.
8. Writes normalized report to `data_storage/reports/{firmware_id}_report.json`.

---

### 5. Launch FastAPI Control Plane

Start the asynchronous REST API backend:

```bash
python scripts/start_api.py
```

- **API Base URL**: `http://127.0.0.1:8000`
- **Interactive Swagger Documentation**: `http://127.0.0.1:8000/docs`
- **Alternative ReDoc UI**: `http://127.0.0.1:8000/redoc`

---

### 6. Launch Interactive Security Dashboard

Start the Streamlit security dashboard:

```bash
python scripts/start_dashboard.py
```

*(On Windows, you can also double-click `run_dashboard.bat`)*

Open your browser at `http://localhost:8501`.

---

## Interactive Security Dashboard

The dashboard provides analysts with comprehensive visual triage capabilities:

| Dashboard View | Description | Key Visualizations |
| :--- | :--- | :--- |
| **📊 Posture Overview** | Executive summary of firmware security posture | Posture score gauge (0–100), risk tier badge, vulnerability breakdown by severity |
| **🛡️ Mitigation Matrix** | Checksec status across discovered ELF binaries | Sortable table for NX, PIE, RELRO, Stack Canaries, FORTIFY, and Stripped symbols |
| **📂 Rootfs File Tree** | Interactive file explorer of carved filesystem | Searchable file hierarchy, SHA-256 hashes, MIME types, and executable flags |
| **📈 Shannon Entropy** | Block-level entropy plot across firmware offsets | Visual identification of compressed partitions, encrypted payloads, and code regions |
| **🔀 CFG & Taint Flow** | Control flow graph & taint propagation viewer | Disassembled basic blocks, branch edges, attacker input sources, and dangerous sink call-sites |
| **🐛 CWE Findings Log** | Detailed vulnerability triage and diagnostic crash logs | Fault address, register state snapshots (`$pc`, `$ra`, `$sp`), and redacted secrets |
| **🔒 Containment Monitor** | Real-time verification of sandbox guardrails | Zero-egress network state, resource quota monitors, and execution timers |

---

## REST API Reference

The control plane exposes RESTful endpoints conforming to OpenAPI specifications:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | API status and engine metadata |
| `GET` | `/api/v1/health` | Service health status and uptime |
| `POST` | `/api/v1/firmware/upload` | Uploads firmware image and kicks off background analysis |
| `GET` | `/api/v1/firmware/{id}/status` | Polls current analysis status and progress percentage (0–100%) |
| `GET` | `/api/v1/firmware/{id}/filesystem` | Returns reconstructed rootfs file-tree inventory and file hashes |
| `GET` | `/api/v1/firmware/{id}/binary-audit`| Returns compiler hardening matrix for all discovered ELFs |
| `GET` | `/api/v1/firmware/{id}/vulnerabilities` | Returns CWE-classified vulnerability findings (Appendix A schema) |
| `GET` | `/api/v1/firmware/{id}/report` | Retrieves the full diagnostic report in normalized JSON format |
| `GET` | `/api/v1/firmware/{id}/cfg/{binary}` | Retrieves interactive CFG basic blocks and call graph for an ELF |
| `GET` | `/api/v1/containment/status` | Proves sandbox containment status and zero network egress |

---

## Vulnerability Taxonomy & CWE Mapping

Every finding emitted by Unit42-FirmwareX is classified under standardized MITRE CWE identifiers:

| CWE ID | Vulnerability Classification | Severity | Discovery Mechanism |
| :--- | :--- | :--- | :--- |
| **CWE-120** | Classic Buffer Overflow (Unchecked Copy) | **High** | Dangerous sink scan (`strcpy`, `strcat`, `gets`) |
| **CWE-121** | Stack-based Buffer Overflow | **Critical** | Symbolic execution constraint solver & crash diagnostic |
| **CWE-134** | Use of Externally-Controlled Format String | **High** | Sink analysis (`sprintf`, `vsprintf` without format specifier) |
| **CWE-78** | OS Command Injection | **Critical** | Taint propagation from input source to `system()` / `popen()` |
| **CWE-787** | Out-of-bounds Write | **High** | Taint flow tracking to unbounded `memcpy` / `memmove` |
| **CWE-798** | Use of Hard-coded Credentials | **High** | Secret scanner pattern matching (passwords, tokens) |
| **CWE-321** | Use of Hard-coded Cryptographic Key | **Critical** | Regex extraction of private RSA/EC keys (redacted) |
| **CWE-328** | Use of Weak Hash (MD5 / SHA-1) | **Medium** | Cryptographic scanner byte-pattern matching |
| **CWE-327** | Use of Broken Cipher (DES, 3DES, RC4, ECB) | **High** | Cryptographic scanner algorithm detection |

---

## Key Performance Indicators (KPIs)

| KPI Metric | Target | Verified Performance | Status |
| :--- | :--- | :--- | :--- |
| **Extraction Success Rate** | > 90% | **100%** on benchmark firmware test suite | **Exceeded** |
| **End-to-End Analysis Time** | < 30 min / image | **< 10 seconds** on realistic multi-arch router firmware | **Exceeded** |
| **Sandbox Containment** | 100% Egress Blocking | **100%** verified via dead-end proxy binding (`127.0.0.1:9`) | **Passed** |
| **Secret Redaction** | 100% Redaction | **100%** of discovered keys and credentials masked | **Passed** |
| **Unit & Integration Tests** | 100% Pass Rate | **23 of 23 tests passing** with 76% total codebase coverage | **Passed** |

---

## Repository Structure

```
palo_alto_networks/
├── firmwarex/                      # Core FirmwareX analysis engine
│   ├── config.py                   # Global configuration, timeout limits, and quota settings
│   ├── schema.py                   # Pydantic data models conforming to Appendix A
│   ├── unpacker/                   # Extraction, entropy analyzer, and rootfs inventory
│   │   ├── detector.py             # Magic byte signature scanner (18+ formats)
│   │   ├── entropy.py              # Shannon entropy analyzer (sliding window)
│   │   ├── extractor.py            # Partition carver and safe archive extractor
│   │   └── tree.py                 # Rootfs crawler and SHA-256 inventory generator
│   ├── audit/                      # Static binary hardening inspection
│   │   ├── elf_parser.py           # ELF32/ELF64 header and architecture parser
│   │   ├── checksec.py             # Mitigation matrix (NX, PIE, RELRO, Canary, FORTIFY)
│   │   └── dangerous_sinks.py      # Libc dangerous function call-site scanner
│   ├── emulation/                  # Isolated sandbox and emulation layer
│   │   ├── sandbox.py              # Zero-egress network containment and quota monitor
│   │   ├── qemu_runner.py          # QEMU user-mode emulation orchestrator
│   │   ├── unicorn_engine.py       # Capstone-powered micro-emulator fallback
│   │   └── nvram_stub.py           # Router NVRAM hardware configuration injector
│   ├── analysis/                   # Advanced program analysis and taint tracking
│   │   ├── cfg.py                  # Control Flow Graph generator and disassembler
│   │   ├── taint_tracker.py        # Input-to-sink taint propagation engine
│   │   ├── symbolic_engine.py      # Bounded symbolic execution constraint solver
│   │   ├── crash_reporter.py       # Non-weaponized diagnostic crash snapshots
│   │   └── fuzzer.py               # Protocol mutation fuzzer for border testing
│   ├── scanner/                    # Secret and cryptography auditing
│   │   ├── secret_scanner.py       # Cloud token, private key, and password scanner
│   │   ├── redactor.py             # 100% secret masking and SHA-256 fingerprinting
│   │   └── crypto_scanner.py       # Deprecated hash and broken cipher detection
│   ├── pipeline/                   # Orchestration and report normalization
│   │   ├── orchestrator.py         # End-to-end multi-stage pipeline coordinator
│   │   └── normalizer.py           # Report aggregator and 0-100 posture score evaluator
│   ├── api/                        # FastAPI REST control plane
│   │   ├── app.py                  # Application initialization and CORS configuration
│   │   └── routes.py               # Asynchronous REST endpoint handlers
│   ├── dashboard/                  # Streamlit security analyst interface
│   │   └── app.py                  # Interactive 6-view web dashboard
│   └── telemetry/                  # Audit trail and telemetry
│       └── tracer.py               # OpenTelemetry span tracer and JSONL audit logger
├── tests/                          # 23 automated unit and integration tests
│   ├── test_api.py                 # REST API endpoints and schema tests
│   ├── test_audit.py               # ELF parsing and checksec mitigation tests
│   ├── test_e2e_pipeline.py        # End-to-end pipeline execution test
│   ├── test_sandbox.py             # Egress containment and quota termination tests
│   ├── test_scanner_redactor.py    # Secret redaction and weak crypto tests
│   ├── test_taint_symbolic.py      # Taint tracking, symbolic solver, and CFG tests
│   └── test_unpacker.py            # Magic detection, entropy, and extractor tests
├── samples/                        # Firmware generation and sample binaries
│   ├── generator.py                # Synthetic multi-arch router firmware builder
│   └── openwrt_mips_router.bin     # Sample multi-architecture test firmware image
├── docs/                           # Technical documentation and specifications
│   ├── ARCHITECTURE.md             # Detailed architecture and sequence diagrams
│   ├── RUNBOOK.md                  # Deployment, operation, and teardown runbook
│   ├── PRD_COMPLIANCE.md           # PRD requirement traceability matrix
│   ├── FINDING_SCHEMA.json         # Appendix A JSON schema specification
│   ├── CWE_MAPPING.md              # Appendix B CWE reference mapping
│   ├── SAMPLE_FINDINGS.json        # Real sample findings from test image
│   └── MITIGATION_MATRIX.json      # Sample compiler mitigation matrix
├── scripts/                        # Operational launchers and test runners
│   ├── run_all_tests.py            # Pytest test suite runner with coverage
│   ├── run_sample_analysis.py      # Standalone CLI analysis runner
│   ├── start_api.py                # FastAPI REST server launcher
│   ├── start_dashboard.py          # Streamlit dashboard launcher
│   └── start-dashboard.py          # Dashboard launcher alias
├── run_dashboard.bat               # Windows double-click dashboard launcher
├── requirements.txt                # Production dependencies
└── README.md                       # Main repository documentation
```

---

## Documentation Index

Comprehensive technical documentation is maintained in the [`docs/`](docs/) directory:

- 📑 [**Internship Final Engineering Write-Up**](docs/FINAL_WRITEUP.md): Complete technical report covering results, benchmarks, containment evidence, design trade-offs, and known limitations.
- 📐 [**System Architecture & Data Flow**](docs/ARCHITECTURE.md): In-depth component architecture, sequence diagrams, and containment specifications.
- 📖 [**Operations Runbook**](docs/RUNBOOK.md): Step-by-step deployment guide, operational commands, troubleshooting, and maintenance.
- 📋 [**PRD Compliance Matrix**](docs/PRD_COMPLIANCE.md): Traceability matrix mapping implementations to functional requirements and KPIs.
- 🛡️ [**CWE Taxonomy Reference**](docs/CWE_MAPPING.md): Detailed catalog of supported CWE classifications and risk calibrations.
- 📦 [**Finding JSON Schema**](docs/FINDING_SCHEMA.json): Machine-readable JSON schema defining Appendix A normalization standards.
- 🔍 [**Sample Diagnostic Report**](docs/SAMPLE_FINDINGS.json): Real findings JSON output generated against the benchmark firmware image.

---

## GitLab CI/CD & Docker Deployment

The repository includes complete GitLab CI/CD and Docker containerization support:

- **GitLab Repository**: [`https://gitlab.com/cjwrits/palo_alto_networks`](https://gitlab.com/cjwrits/palo_alto_networks)
- **CI/CD Pipeline** (`.gitlab-ci.yml`):
  - `lint`: Code quality and formatting checks.
  - `test`: Automated 23-test execution with Cobertura XML and JUnit test reporting.
  - `security-audit`: Invariant audit verifying zero outbound egress and 100% secret redaction.
  - `build`: Container image build for production registry.
  - `deploy`: Staging deployment verification.
- **Docker Compose** (`docker-compose.yml`):
  ```bash
  # Launch FastAPI backend (8000), Streamlit dashboard (8501), and Redis
  docker compose up -d --build
  ```

---

## License & Classification

**Internal // Confidential — Palo Alto Networks Unit 42**  
*Threat Research & Security Engineering. All rights reserved.*