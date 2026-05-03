import uuid
import ipaddress
from backend.models import Tool
from backend.validation import validate_target
from backend.tasks import run_nmap, run_nuclei
from backend.db import get_db
from backend.models import Target, JobDefinition, JobExecution, ExecutionTool, Tenant



def _detect_type(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return "domain"
    host = target.split(":")[0]
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        return "domain"


def ingest_target(target_url: str, tenant_id: str):
    tenant_uuid = uuid.UUID(tenant_id)

    is_valid, reason = validate_target(target_url)
    if not is_valid:
        return {"status": "rejected", "reason": reason}

    normalized = target_url.strip().lower()
    target_type = _detect_type(normalized)

    with get_db() as db:
        # validate tenant exists
        tenant_exists = (
            db.query(Tenant)
            .filter(Tenant.id == tenant_uuid)
            .first()
)

        if not tenant_exists:
            return {"status": "error", "message": "Invalid tenant_id"}

        # Reuse or create target
        target = db.query(Target).filter(Target.value == normalized).first()
        if not target:
            target = Target(type=target_type, value=normalized)
            db.add(target)
            db.flush()

        version = (
            db.query(JobDefinition)
            .filter_by(tenant_id=tenant_uuid, target_id=target.id)
            .count()
        ) + 1

        job_def = JobDefinition(
            tenant_id=tenant_uuid,
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
        
        nmap_tool = db.query(Tool).filter(Tool.name == "Nmap").first()
        nuclei_tool = db.query(Tool).filter(Tool.name == "Nuclei").first()
        metasploit_tool = db.query(Tool).filter(Tool.name == "Metasploit").first()
        semgrep_tool = db.query(Tool).filter(Tool.name == "Semgrep").first()
        langgraph_tool = db.query(Tool).filter(Tool.name == "LangGraph Agent").first()

        if not nmap_tool or not nuclei_tool or not metasploit_tool or not semgrep_tool or not langgraph_tool:
            return {"status": "error", "message": "Tools not seeded in DB"}

        nmap_et = ExecutionTool(
            job_execution_id=job_exec.id,
            tool_id=nmap_tool.id,
            execution_order=1,
            status="queued",
        )
        nuclei_et = ExecutionTool(
            job_execution_id=job_exec.id,
            tool_id=nuclei_tool.id,
            execution_order=2,
            status="queued",
        )
        metasploit_et = ExecutionTool(
            job_execution_id=job_exec.id,
            tool_id=metasploit_tool.id,
            execution_order=3,
            status="queued",
        )
        semgrep_et = ExecutionTool(
            job_execution_id=job_exec.id,
            tool_id=semgrep_tool.id,
            execution_order=4,
            status="queued",
        )
        langgraph_et = ExecutionTool(
            job_execution_id=job_exec.id,
            tool_id=langgraph_tool.id,
            execution_order=5,
            status="queued",
        )

        db.add_all([nmap_et, nuclei_et, metasploit_et, semgrep_et, langgraph_et])
        db.flush()

        # Trigger Celery
        task1 = run_nmap.delay(normalized, str(nmap_et.id))
        task2 = run_nuclei.delay(normalized, str(nuclei_et.id))
        task3 = run_metasploit.delay(normalized, str(metasploit_et.id))
        task4 = run_semgrep.delay(normalized, str(semgrep_et.id))
        task5 = run_langgraph.delay(normalized, str(langgraph_et.id))


        nmap_et.celery_task_id = task1.id
        nuclei_et.celery_task_id = task2.id
        metasploit_et.celery_task_id = task3.id
        semgrep_et.celery_task_id = task4.id
        langgraph_et.celery_task_id = task5.id

        job_id = str(job_exec.id)

    return {
        "status": "accepted",
        "job_id": job_id,
        "job_state": "queued",
    }