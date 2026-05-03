import uuid
from sqlalchemy.orm import Session
from backend.models import ExecutionTool, JobExecution, JobDefinition
from backend.models import Finding
from sqlalchemy.orm import Session

def create_job_execution(db: Session, tenant_id: uuid.UUID, target_url: str):
    job = JobExecution(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        target_url=target_url,
        status="pending"
    )
    db.add(job)
    db.flush()
    return job

def get_tool_by_name(db, name):
    return db.query(Tool).filter(Tool.name == name).first()


# Fixed UUIDs matching the seed data in db/schema.sql
#NMAP_TOOL_ID      = uuid.UUID("00000000-0000-0000-0000-000000000002")
#NUCLEI_TOOL_ID    = uuid.UUID("00000000-0000-0000-0000-000000000003")
#HTTPX_TOOL_ID     = uuid.UUID("00000000-0000-0000-0000-000000000004")


def get_job_execution(db: Session, job_id: str, tenant_id: uuid.UUID):
    return (
        db.query(JobExecution)
        .join(JobDefinition, JobExecution.job_definition_id == JobDefinition.id)
        .filter(
            JobExecution.id == uuid.UUID(job_id),
            JobDefinition.tenant_id == tenant_id
        )
        .first()
    )

def get_execution_tool(db: Session, execution_tool_id: str, tenant_id: uuid.UUID):
    return db.query(ExecutionTool).filter(ExecutionTool.id == execution_tool_id, ExecutionTool.tenant_id ==tenant_id).first()


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

def get_findings_by_job(db: Session, job_execution_id: str, tenant_id: uuid.UUID):
    return (
        db.query(Finding)
        .join(JobExecution, Finding.job_execution_id == JobExecution.id)
        .join(JobDefinition, JobExecution.job_definition_id == JobDefinition.id)
        .filter(
            JobExecution.id == uuid.UUID(job_execution_id),
            JobDefinition.tenant_id == tenant_id
        )
        .order_by(Finding.discovered_at.desc())
        .all()
    )