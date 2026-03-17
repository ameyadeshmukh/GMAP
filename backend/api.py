from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from ingestion import ingest_target
from db import get_db
from store import get_job_execution
from models import ExecutionTool
from audit.router import router as audit_router


class TargetRequest(BaseModel):
    target_url: str


app = FastAPI(title="GMAP API")
app.include_router(audit_router)


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

        return {
            "job_id": str(job_exec.id),
            "status": job_exec.status,
            "started_at": job_exec.started_at,
            "completed_at": job_exec.completed_at,
            "tools": [
                {
                    "execution_tool_id": str(t.id),
                    "tool_id": str(t.tool_id),
                    "order": t.execution_order,
                    "status": t.status,
                    "celery_task_id": t.celery_task_id,
                    "started_at": t.started_at,
                    "completed_at": t.completed_at,
                }
                for t in tools
            ],
        }
