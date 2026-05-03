import pytest
from backend.tasks import run_scan
from sqlalchemy import text
from backend.models import ToolRun, ExecutionTool, JobExecution, JobDefinition
import uuid
#Simulate Tool output
def sample_scan():
    return {
        "scan_type": "nmap",
        "open_ports": [22, 443],
        "vulnerabilities": []
    }

def test_simulated_tool_output_validation():
    data = sample_scan()

    assert data["scan_type"] == "nmap"
    assert isinstance(data["open_ports"], list)

#DB JSONB Storage + retrieval test
def test_db_roundtrip(db):
    # 1. Create JobDefinition (REQUIRED)
    job_def = JobDefinition(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),   
        target_id=uuid.uuid4(),   
        name="test_job",
        version_number=1,
        is_active=True
    )
    db.add(job_def)
    db.flush()

    # 2. Create JobExecution (NOW VALID)
    job_exec = JobExecution(
        id=uuid.uuid4(),
        job_definition_id=job_def.id,
        status="queued"
    )
    db.add(job_exec)
    db.flush()

    # 3. Create ExecutionTool
    exec_tool = ExecutionTool(
        id=uuid.uuid4(),
        job_execution_id=job_exec.id,
        status="completed"
    )
    db.add(exec_tool)
    db.flush()

    # 4. Create ToolRun
    tool_run = ToolRun(
        execution_tool_id=exec_tool.id,
        raw_output_json=sample_scan(),
        exit_code=0
    )
    db.add(tool_run)
    db.flush()

    # 5. Validate
    result = db.query(ToolRun).first()
    assert result.raw_output_json["scan_type"] == "nmap"
    

#End-to-End test (API-> DB-> Celery-> AI-> DB-> Query Layer)
#Api call
def test_full_pipeline_api(client):
    response = client.post("/scan", json=sample_scan())

    assert response.status_code == 200

#Verify AI/DB insert
def test_ai_output(db):
    result = db.execute(text("""
    SELECT summary_text
    FROM ai_analyses
    ORDER BY created_at DESC
    LIMIT 1;
""")).mappings().fetchall()
    
    assert result[0]["summary_text"] is not None

#Verify streamlit dashboard view
def test_materialized_view(db):
    result = db.execute(text("SELECT * FROM mv_findings_by_severity")).fetchall()
    assert result is not None