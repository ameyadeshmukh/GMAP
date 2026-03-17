import uuid
from sqlalchemy.orm import Session
from models import ExecutionTool, JobExecution

# Fixed UUIDs matching the seed data in db/schema.sql
DEFAULT_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
NMAP_TOOL_ID      = uuid.UUID("00000000-0000-0000-0000-000000000002")
NUCLEI_TOOL_ID    = uuid.UUID("00000000-0000-0000-0000-000000000003")
HTTPX_TOOL_ID     = uuid.UUID("00000000-0000-0000-0000-000000000004")


def get_job_execution(db: Session, job_id: str) -> JobExecution | None:
    return db.query(JobExecution).filter(JobExecution.id == job_id).first()


def get_execution_tool(db: Session, execution_tool_id: str) -> ExecutionTool | None:
    return db.query(ExecutionTool).filter(ExecutionTool.id == execution_tool_id).first()


def all_tools_done(db: Session, job_execution_id: str) -> bool:
    """Returns True when every execution_tool for this job has reached a terminal state."""
    incomplete = (
        db.query(ExecutionTool)
        .filter(
            ExecutionTool.job_execution_id == job_execution_id,
            ExecutionTool.status.notin_(["completed", "failed", "cancelled"]),
        )
        .count()
    )
    return incomplete == 0


def any_tool_failed(db: Session, job_execution_id: str) -> bool:
    return (
        db.query(ExecutionTool)
        .filter(
            ExecutionTool.job_execution_id == job_execution_id,
            ExecutionTool.status == "failed",
        )
        .count()
        > 0
    )
