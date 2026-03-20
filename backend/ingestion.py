import ipaddress

from validation import validate_target
from tasks import run_nmap, run_nuclei
from db import get_db
from models import Target, JobDefinition, JobExecution, ExecutionTool
from store import DEFAULT_TENANT_ID, NMAP_TOOL_ID, NUCLEI_TOOL_ID


def _detect_type(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return "domain"
    host = target.split(":")[0]
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        return "domain"


def ingest_target(target_url: str):
    is_valid, reason = validate_target(target_url)
    if not is_valid:
        return {"status": "rejected", "reason": reason}

    normalized = target_url.strip().lower()
    target_type = _detect_type(normalized)

    with get_db() as db:
        # Reuse existing target row or create a new one
        target = db.query(Target).filter(Target.value == normalized).first()
        if not target:
            target = Target(type=target_type, value=normalized)
            db.add(target)
            db.flush()

        # Version the job definition (1-indexed, increments per target)
        version = (
            db.query(JobDefinition)
            .filter_by(tenant_id=DEFAULT_TENANT_ID, target_id=target.id)
            .count()
        ) + 1

        job_def = JobDefinition(
            tenant_id=DEFAULT_TENANT_ID,
            target_id=target.id,
            name=normalized,
            version_number=version,
        )
        db.add(job_def)
        db.flush()

        exec_count = (
            db.query(JobExecution)
            .filter_by(job_definition_id=job_def.id)
            .count()
        ) + 1

        job_exec = JobExecution(
            job_definition_id=job_def.id,
            status="queued",
            execution_number=exec_count,
        )
        db.add(job_exec)
        db.flush()

        nmap_et = ExecutionTool(
            job_execution_id=job_exec.id,
            tool_id=NMAP_TOOL_ID,
            execution_order=1,
            status="queued",
        )
        nuclei_et = ExecutionTool(
            job_execution_id=job_exec.id,
            tool_id=NUCLEI_TOOL_ID,
            execution_order=2,
            status="queued",
        )
        db.add_all([nmap_et, nuclei_et])
        db.flush()

        # TODO: Replace with a sequential Celery chain once the LangGraph agent is in place.
        # Intended order: nmap → agent decision → httpx → agent decision → nuclei
        task1 = run_nmap.delay(normalized, str(nmap_et.id))
        task2 = run_nuclei.delay(normalized, str(nuclei_et.id))

        nmap_et.celery_task_id = task1.id
        nuclei_et.celery_task_id = task2.id

        job_id = str(job_exec.id)

    return {
        "status": "accepted",
        "job_id": job_id,
        "job_state": "queued",
    }
