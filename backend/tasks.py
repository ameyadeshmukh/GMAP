import time
from datetime import datetime, UTC

from celery_app import app
from db import get_db
from models import ExecutionTool, JobExecution, ToolRun
from store import all_tools_done, any_tool_failed


def _mark_running(db, execution_tool_id: str) -> str:
    """Set execution_tool to running; set parent job_execution to running if still queued.
    Returns the job_execution_id as a string."""
    et = db.query(ExecutionTool).filter_by(id=execution_tool_id).first()
    if not et:
        raise ValueError(f"ExecutionTool {execution_tool_id} not found")
    et.status = "running"
    et.started_at = datetime.now(UTC)
    job_exec = db.query(JobExecution).filter_by(id=et.job_execution_id).first()
    if job_exec and job_exec.status == "queued":
        job_exec.status = "running"
        job_exec.started_at = datetime.now(UTC)
    return str(et.job_execution_id)


def _mark_done(db, execution_tool_id: str, result: dict, job_execution_id: str):
    """Set execution_tool to completed, write ToolRun, and close the job if all tools finished."""
    et = db.query(ExecutionTool).filter_by(id=execution_tool_id).first()
    if et:
        et.status = "completed"
        et.completed_at = datetime.now(UTC)
        db.add(ToolRun(
            execution_tool_id=et.id,
            raw_output_json=result,
            exit_code=0,
        ))
        db.flush()

    if all_tools_done(db, job_execution_id):
        final_status = "failed" if any_tool_failed(db, job_execution_id) else "completed"
        job_exec = db.query(JobExecution).filter_by(id=job_execution_id).first()
        if job_exec:
            job_exec.status = final_status
            job_exec.completed_at = datetime.now(UTC)


@app.task
def run_nmap(target: str, execution_tool_id: str):
    with get_db() as db:
        job_execution_id = _mark_running(db, execution_tool_id)

    # TODO: Replace with real nmap subprocess call
    print(f"[nmap] Scanning {target}...")
    time.sleep(2)
    result = {"tool": "nmap", "open_ports": [80, 443, 8080]}

    with get_db() as db:
        _mark_done(db, execution_tool_id, result, job_execution_id)

    return result


@app.task
def run_nuclei(target: str, execution_tool_id: str):
    with get_db() as db:
        job_execution_id = _mark_running(db, execution_tool_id)

    # TODO: Replace with real nuclei subprocess call
    print(f"[nuclei] Scanning {target}...")
    time.sleep(3)
    result = {"tool": "nuclei", "cves_found": ["CVE-XXXX-XXXXX"]}

    with get_db() as db:
        _mark_done(db, execution_tool_id, result, job_execution_id)

    return result
