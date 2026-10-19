# Operations Runbook & Deployment Guide
**Project Unit42-FirmwareX | Palo Alto Networks — Unit 42**
*Automated IoT / Embedded Firmware Attack Surface & Vulnerability Analysis Engine*

---

## 1. System Requirements & Prerequisites

- **Operating System**: Windows 10/11, Linux (Ubuntu 20.04+), or macOS
- **Python**: Python 3.10+ (tested and verified on Python 3.13)
- **Dependencies**:
  - `pyelftools` (ELF header & binary inspection)
  - `capstone` (Cross-architecture multi-engine disassembler)
  - `fastapi`, `uvicorn`, `streamlit` (API control plane & dashboard UI)
  - `pydantic>=2.0`, `pydantic-settings` (Schema validation & data modeling)
  - `psutil` (Resource quota enforcement & process tracking)
  - `networkx` (Control flow graph generation & cycle analysis)
  - `rich` (Terminal formatting and audit reports)

---

## 2. Installation & Quickstart

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```
*(Or install core dependencies directly: `pip install pyelftools capstone fastapi uvicorn streamlit pydantic pydantic-settings psutil networkx rich`)*

### Step 2: Verify Test Suite
Run the 23-test verification suite with test coverage:
```bash
python scripts/run_all_tests.py
```
Or directly with pytest:
```bash
pytest tests -v
```

---

## 3. Generating Sample Open-Source IoT Firmware

Unit42-FirmwareX comes with a realistic multi-architecture firmware generator that compiles an authentic U-Boot `uImage` container embedding a Linux rootfs with MIPS, ARM, and x86 binaries, hardcoded cloud credentials, and legacy cryptographic primitives:

```bash
python samples/generator.py
```
Output:
```
Generated sample firmware image at samples/openwrt_mips_router.bin (2,083 bytes)
```

---

## 4. Running Firmware Analysis via CLI

Analyze any firmware image directly from the command line:

```bash
python scripts/run_sample_analysis.py samples/openwrt_mips_router.bin
```

This command will:
1. Unpack the image container, calculate Shannon entropy, and carve rootfs.
2. Build the filesystem inventory and discover ELF binaries.
3. Perform checksec hardening audit (NX, PIE, RELRO, Canary, Fortify) on all ELFs.
4. Scan dangerous memory and command execution sinks.
5. Emulate priority binaries in an isolated sandbox with mock NVRAM stubs.
6. Trace attacker taint to sinks and solve bounded symbolic paths for crash state.
7. Scan for embedded secrets and weak cryptographic primitives with 100% redaction.
8. Persist the normalized JSON report to `data_storage/reports/{firmware_id}_report.json`.

---

## 5. Starting the REST API Service

Launch the FastAPI control plane:

```bash
python scripts/start_api.py
```
- **API Base URL**: `http://127.0.0.1:8000`
- **Interactive OpenAPI Documentation (Swagger UI)**: `http://127.0.0.1:8000/docs`
- **Alternative ReDoc UI**: `http://127.0.0.1:8000/redoc`

### Key Endpoints:
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/firmware/upload` | Ingests `.bin`/`.img` image and dispatches background worker |
| `GET` | `/api/v1/firmware/{id}/status` | Queries real-time analysis progress and stage |
| `GET` | `/api/v1/firmware/{id}/filesystem` | Returns reconstructed rootfs file-tree inventory |
| `GET` | `/api/v1/firmware/{id}/binary-audit` | Returns compiler mitigation matrix across ELFs |
| `GET` | `/api/v1/firmware/{id}/vulnerabilities` | Returns CWE-classified normalized findings (Appendix A) |
| `GET` | `/api/v1/firmware/{id}/report` | Retrieves the full diagnostic posture report |
| `GET` | `/api/v1/firmware/{id}/cfg/{binary}` | Returns interactive CFG basic blocks and call graph |
| `GET` | `/api/v1/containment/status` | Proves sandbox isolation and zero network egress |

---

## 6. Launching the Interactive Security Dashboard

Start the Streamlit security analyst interface:

```bash
python scripts/start_dashboard.py
```
Access the dashboard in your browser at:
`http://localhost:8501`

### Dashboard Capabilities:
- **📊 Posture Overview**: Real-time firmware posture score (0-100), risk breakdown charts, and CWE distribution.
- **🛡️ Binary Mitigation Matrix**: Sortable table inspecting NX, PIE, RELRO, Canary, and FORTIFY flags per binary.
- **📂 File Tree Inventory**: Interactive search and hash inspector for all extracted files in rootfs.
- **🔀 Interactive CFG Visualizer**: Renders disassembled basic blocks, jump branches, taint paths, and sink call-sites.
- **🐛 Findings & Crash Diagnostic Log**: Filterable list of CWE findings with diagnostic register dumps (`$pc`, `$ra`, `$sp`, offset).
- **🔒 Containment & Quotas**: Live verification of sandbox isolation policies and resource limit monitors.
- **📤 Upload Portal**: Direct file drag-and-drop to trigger new firmware analysis jobs.

---

## 7. Containment & Guardrails Verification

Verify the sandbox isolation and quota enforcement policies:
```bash
pytest tests/test_sandbox.py -v
```
This test proves:
1. `test_egress_containment_proof`: Network proxy guard is strictly locked to non-routable port `127.0.0.1:9`.
2. `test_sandbox_quota_timeout`: Untrusted processes exceeding execution time or memory quotas are killed immediately with exit code `-9`.

---

## 8. Teardown & Maintenance

To clear all extracted files, uploaded firmware images, and logs:
```bash
# Windows PowerShell
Remove-Item -Recurse -Force data_storage/extracted/*
Remove-Item -Recurse -Force data_storage/uploads/*
Remove-Item -Recurse -Force data_storage/reports/*
Remove-Item -Recurse -Force data_storage/logs/*

# Linux / macOS
rm -rf data_storage/extracted/* data_storage/uploads/* data_storage/reports/* data_storage/logs/*
```
