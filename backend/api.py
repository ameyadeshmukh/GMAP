from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc

from backend.ingestion import ingest_target
from backend.db import get_db, Base, engine
from backend.store import (
    DEFAULT_TENANT_ID,
    GRAPH_TOOL_ID,
    HTTPX_TOOL_ID,
    NMAP_TOOL_ID,
    NUCLEI_TOOL_ID,
    get_job_execution,
)
from backend.models import ExecutionTool, JobExecution, ToolRun, ReviewRequest, Tenant, Tool
from backend.audit.router import router as audit_router


class TargetRequest(BaseModel):
    target_url: str


class ReviewDecision(BaseModel):
    decision: str


app = FastAPI(title="GMAP API")
app.include_router(audit_router)


@app.on_event("startup")
def create_tables():
    Base.metadata.create_all(bind=engine)
    with get_db() as db:
        if not db.query(Tenant).filter_by(id=DEFAULT_TENANT_ID).first():
            db.add(Tenant(id=DEFAULT_TENANT_ID, name="default", subscription_tier="free"))

        seed_tools = [
            (NMAP_TOOL_ID, "nmap", "7.94", "scanner"),
            (NUCLEI_TOOL_ID, "nuclei", "3.0", "scanner"),
            (HTTPX_TOOL_ID, "httpx", "1.3", "scanner"),
            (GRAPH_TOOL_ID, "graph", "1.0", "scanner"),
        ]
        for tool_id, name, version, category in seed_tools:
            if not db.query(Tool).filter_by(id=tool_id).first():
                db.add(Tool(id=tool_id, name=name, version=version, category=category))


@app.get("/")
def read_root():
    return {"message": "GMAP API is running!"}


@app.post("/targets")
async def submit_target(req: TargetRequest):
    return ingest_target(target_url=req.target_url)


@app.get("/jobs")
def list_jobs(limit: int = 20):
    with get_db() as db:
        jobs = (
            db.query(JobExecution)
            .order_by(desc(JobExecution.started_at))
            .limit(limit)
            .all()
        )
        return [
            {
                "job_id": str(j.id),
                "status": j.status,
                "started_at": j.started_at,
                "completed_at": j.completed_at,
            }
            for j in jobs
        ]


@app.get("/jobs/{job_id}")
def get_job(job_id: str):
    with get_db() as db:
        job_exec = get_job_execution(db, job_id)
        if not job_exec:
            raise HTTPException(status_code=404, detail="Job not found")

        tools = (
            db.query(ExecutionTool)
            .filter_by(job_execution_id=job_exec.id)
            .order_by(ExecutionTool.execution_order)
            .all()
        )

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
            "tools": tools_data,
        }


@app.get("/jobs/{job_id}/review")
def get_review(job_id: str):
    with get_db() as db:
        req = db.query(ReviewRequest).filter_by(job_execution_id=job_id).first()
        if not req:
            raise HTTPException(status_code=404, detail="No pending review for this job")
        return {
            "job_id": job_id,
            "vulnerabilities": req.vulnerabilities,
            "decision": req.decision,
        }


@app.post("/jobs/{job_id}/review")
def submit_review(job_id: str, body: ReviewDecision):
    with get_db() as db:
        req = db.query(ReviewRequest).filter_by(job_execution_id=job_id).first()
        if not req:
            raise HTTPException(status_code=404, detail="No pending review for this job")
        req.decision = body.decision
    return {"status": "ok", "decision": body.decision}