import time
from datetime import datetime, timezone
from backend.celery_app import app
from backend.db import get_db
from backend.models import ExecutionTool, JobExecution, ToolRun
from backend.store import all_tools_done, any_tool_failed
from backend.celery_app import celery_app as celery

def _mark_running(db, execution_tool_id: str) -> str:
    """Set execution_tool to running; set parent job_execution to running if still queued.
    Returns the job_execution_id as a string."""
    et = db.query(ExecutionTool).filter_by(id=execution_tool_id).first()
    if not et:
        raise ValueError(f"ExecutionTool {execution_tool_id} not found")
    et.status = "running"
    et.started_at = datetime.now(timezone.utc)
    job_exec = db.query(JobExecution).filter_by(id=et.job_execution_id).first()
    if job_exec and job_exec.status == "queued":
        job_exec.status = "running"
        job_exec.started_at = datetime.now(timezone.utc)
    return str(et.job_execution_id)


def _mark_done(db, execution_tool_id: str, result: dict, job_execution_id: str, input_payload: dict):
    """Set execution_tool to completed, write ToolRun, and close the job if all tools finished."""
    et = db.query(ExecutionTool).filter_by(id=execution_tool_id).first()
    if et:
        et.status = "completed"
        et.completed_at = datetime.now(timezone.utc)
        db.add(ToolRun(
            execution_tool_id=et.id,
            input_parameters=input_payload, # added tool input parameters
            raw_output_json=result,
            exit_code=0,
        ))
        db.flush()

    if all_tools_done(db, job_execution_id):
        final_status = "failed" if any_tool_failed(db, job_execution_id) else "completed"
        job_exec = db.query(JobExecution).filter_by(id=job_execution_id).first()
        if job_exec:
            job_exec.status = final_status
            job_exec.completed_at = datetime.now(timezone.utc)

# function for standardized JSON tool output
def build_json_tool_result(tool_name: str, execution_id: str, status: str, data: dict = None, error: dict = None):
    return {
        "tool_name": tool_name,
        "execution_id": execution_id,
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data or {},
        "error": error
    }

@app.task
def run_nmap(target: str, execution_tool_id: str):
    with get_db() as db:
        job_execution_id = _mark_running(db, execution_tool_id)

    # TODO: Replace with real nmap subprocess call
    print(f"[nmap] Scanning {target}...")
    time.sleep(2)
    input_payload = {
        "target": target,
        "execution_id": execution_tool_id,
        "options": {}   # tool parameters
    }

    result = build_json_tool_result(
        tool_name="nmap",
        execution_id=execution_tool_id,
        status="success",
        data={"open_ports": [80, 443, 8080]}
    )

    with get_db() as db:
        _mark_done(db, execution_tool_id, result, job_execution_id, input_payload)

    return result


@app.task
def run_nuclei(target: str, execution_tool_id: str):
    with get_db() as db:
        job_execution_id = _mark_running(db, execution_tool_id)

    # TODO: Replace with real nuclei subprocess call
    print(f"[nuclei] Scanning {target}...")
    time.sleep(3)
    input_payload = {
        "target": target,
        "execution_id": execution_tool_id,
        "options": {}   # tool parameters
    }

    result = build_json_tool_result(
        tool_name="nuclei",
        execution_id=execution_tool_id,
        status="success",
        data={"cves_found": ["CVE-XXXX-XXXXX"]}
    )

    with get_db() as db:
        _mark_done(db, execution_tool_id, result, job_execution_id, input_payload)

    return result


@celery.task(bind=True)
def run_scan(self, payload):
    print(f"Running scan with payload: {payload}")

    #Validation
    if not isinstance(payload, dict):
        raise ValueError("Payload must be a dictionary")

    if "scan_type" not in payload:
        raise ValueError("Missing scan_type")

    #Simulated processing
    return {
        "status": "completed",
        "summary": f"Processed {payload['scan_type']}",
        "data": payload
    }