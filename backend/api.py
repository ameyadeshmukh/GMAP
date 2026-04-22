from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List
from sqlalchemy import desc
import uuid
#from tasks import run_metasploit, run_semgrep, run_langgraph
from ingestion import ingest_target
from db import get_db
from store import get_job_execution
from models import ExecutionTool, ToolRun
from audit.router import router as audit_router
from store import get_findings_by_job
from models import Finding
from tasks import run_scan

class TargetRequest(BaseModel):
    target_url: str
    tenant_id: str

class Vulnerability(BaseModel):
    cve: str = Field(..., example="CVE-2024-1234")
    severity: str = Field(..., example="high")

class ScanOutput(BaseModel):
    scan_type: str = Field(..., example="nmap")
    open_ports: List[int]
    vulnerabilities: List[Vulnerability]

app = FastAPI(title="GMAP API")
app.include_router(audit_router)


@app.get("/")
def read_root():
    return {"message": "GMAP API is running!"}


@app.post("/targets")
async def submit_target(req: TargetRequest):
    return ingest_target(
        target_url=req.target_url,
        tenant_id=req.tenant_id 
        )


@app.get("/jobs/{job_id}")
def get_job(job_id: str, tenant_id: str):
    tenant_uuid = uuid.UUID(tenant_id)
    with get_db() as db:
        job_exec = get_job_execution(db, job_id, tenant_uuid)
        if not job_exec:
            raise HTTPException(status_code=404, detail="Job not found")

        tools = (
            db.query(ExecutionTool)
            .filter_by(job_execution_id=job_exec.id)
            .order_by(ExecutionTool.execution_order)
            .all()
        )

        # get our structured output for each tool run in the job
        tools_data = []
        for t in tools:
            tool_run = (
                db.query(ToolRun)
                .filter(ToolRun.execution_tool_id == t.id)
                .order_by(desc(ToolRun.created_at))
                .first()
            )

            tools_data.append({
                "execution_tool_id": str(t.id),
                "tool_id": str(t.tool_id),
                "order": t.execution_order,
                "status": t.status,
                "celery_task_id": t.celery_task_id,
                "started_at": t.started_at,
                "completed_at": t.completed_at,

                "input": tool_run.input_parameters if tool_run else None,
                "output": tool_run.raw_output_json if tool_run else None,
            })

        return {
            "job_id": str(job_exec.id),
            "status": job_exec.status,
            "started_at": job_exec.started_at,
            "completed_at": job_exec.completed_at,
            "tools": tools_data
        }

@app.get("/findings")
def get_findings(job_id: str, tenant_id: str):
    tenant_uuid = uuid.UUID(tenant_id)

    with get_db() as db:
        findings = get_findings_by_job(db, job_id, tenant_uuid)

        return [
            {
                "id": str(f.id),
                "job_execution_id": str(f.job_execution_id),
                "tool_run_id": str(f.tool_run_id),
                "cve_id": f.cve_id,
                "title": f.title,
                "description": f.description,
                "severity_score": f.severity_score,
                "severity_label": f.severity_label,
                "confidence_score": f.confidence_score,
                "status": f.status,
                "discovered_at": f.discovered_at,
            }
            for f in findings
        ]

@app.post("/run-job/{job_id}")
def run_job(job_id: str):
    task = run_scan.delay(job_id)
    return {"task_id": task.id}

@app.post("/scan")
def upload_scan(data: ScanOutput):
    return {
        "status": "validated",
        "scan_type": data.scan_type,
        "ports_count": len(data.open_ports),
        "vuln_count": len(data.vulnerabilities)
    }
    