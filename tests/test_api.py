"""
Unit Tests — REST API Control Plane (PRD Section 8.1)
"""

from fastapi.testclient import TestClient
from pathlib import Path
from firmwarex.api.app import app
from firmwarex.config import settings

client = TestClient(app)

def test_api_health_and_root():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

    root_res = client.get("/")
    assert root_res.status_code == 200
    assert "Unit42" in root_res.json()["project"]

def test_containment_status_endpoint():
    res = client.get("/api/v1/containment/status")
    assert res.status_code == 200
    data = res.json()
    assert data["sandbox_isolation"] == "ACTIVE"
    assert "DENIED" in data["network_egress"]

def test_upload_and_pipeline_api():
    sample_fw = Path("samples/openwrt_mips_router.bin")
    assert sample_fw.exists()

    with open(sample_fw, "rb") as f:
        res = client.post(
            "/api/v1/firmware/upload",
            files={"file": ("openwrt_mips_router.bin", f, "application/octet-stream")}
        )

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "enqueued"
    assert "firmware_id" in data
    firmware_id = data["firmware_id"]

    # Poll status
    status_res = client.get(f"/api/v1/firmware/{firmware_id}/status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["firmware_id"] == firmware_id

def test_api_report_and_audit_endpoints():
    # Use existing analyzed firmware from e2e test
    report_files = list(settings.REPORT_DIR.glob("*_report.json"))
    assert len(report_files) > 0
    f_id = report_files[0].stem.replace("_report", "")

    # 1. Test PRD 8.1 /firmware/{id} summary endpoint
    res_summary = client.get(f"/api/v1/firmware/{f_id}")
    assert res_summary.status_code == 200
    summary_data = res_summary.json()
    assert summary_data["firmware_id"] == f_id
    assert "metadata" in summary_data

    # 2. Test PRD 8.1 /jobs/{jobId} endpoint
    res_job = client.get(f"/api/v1/jobs/{f_id}")
    assert res_job.status_code == 200
    assert res_job.json()["stage"] == "completed"

    # 3. Test binary-audit
    res = client.get(f"/api/v1/firmware/{f_id}/binary-audit")
    assert res.status_code == 200
    data = res.json()
    assert "binaries" in data
    assert len(data["binaries"]) >= 1

    # 4. Test filesystem inventory
    res_fs = client.get(f"/api/v1/firmware/{f_id}/filesystem")
    assert res_fs.status_code == 200
    fs_data = res_fs.json()
    assert "nodes" in fs_data
    assert fs_data["total_nodes"] > 0

    # 5. Test vulnerabilities
    res_v = client.get(f"/api/v1/firmware/{f_id}/vulnerabilities")
    assert res_v.status_code == 200
    v_data = res_v.json()
    assert "findings" in v_data
    assert v_data["count"] > 0

    # Filtered vulnerabilities query
    res_vf = client.get(f"/api/v1/firmware/{f_id}/vulnerabilities?risk=critical")
    assert res_vf.status_code == 200

    # 4. Test full report
    res_rep = client.get(f"/api/v1/firmware/{f_id}/report")
    assert res_rep.status_code == 200
    assert "overall_posture_score" in res_rep.json()

    # 5. Test CFG
    res_cfg = client.get(f"/api/v1/firmware/{f_id}/cfg/httpd")
    assert res_cfg.status_code == 200
    cfg_data = res_cfg.json()
    assert "nodes" in cfg_data
    assert len(cfg_data["nodes"]) > 0
