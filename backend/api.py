from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc

from backend.ingestion import ingest_target
from backend.db import get_db
from backend.store import get_job_execution
from backend.models import ExecutionTool, ToolRun
from backend.audit.router import router as audit_router


class TargetRequest(BaseModel):
    target_url: str


class ReviewDecision(BaseModel):
    decision: str  # approve, skip, abort


app = FastAPI(title="GMAP API")
app.include_router(audit_router)


@app.on_event("startup")
def create_tables():
    Base.metadata.create_all(bind=engine)


@app.get("/")
def read_root():
    return {"message": "GMAP API is running!"}


@app.post("/targets")
async def submit_target(req: TargetRequest):
    return ingest_target(target_url=req.target_url)


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


@app.get("/jobs/{job_id}/review")
def get_review(job_id: str):
    with get_db() as db:
        req = db.query(ReviewRequest).filter_by(job_execution_id=job_id).first()
        if not req:
            raise HTTPException(status_code=404, detail="No pending review for this job")
        return {
            "job_id": job_id,
            "vulnerabilities": req.vulnerabilities,
            "msf_modules": req.msf_modules,
            "decision": req.decision,
        }


@app.post("/jobs/{job_id}/review")
def submit_review(job_id: str, body: ReviewDecision):
    if body.decision not in ("approve", "skip", "abort"):
        raise HTTPException(status_code=400, detail="decision must be approve, skip, or abort")
    with get_db() as db:
        req = db.query(ReviewRequest).filter_by(job_execution_id=job_id).first()
        if not req:
            raise HTTPException(status_code=404, detail="No pending review for this job")
        if req.decision:
            raise HTTPException(status_code=409, detail="Decision already submitted")
        req.decision = body.decision
    return {"status": "ok", "decision": body.decision}
