import uuid
from fastapi import APIRouter, HTTPException, Query
from backend.db import get_db
from .models import AuditLog

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/jobs/{job_id}")
def audit_list_for_job(
    job_id: str,
    limit: int = Query(default=500, ge=1, le=2000),
):
    try:
        job_uuid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="job_id must be a UUID")

    with get_db() as db:
        rows = (
            db.query(AuditLog)
            .filter(AuditLog.entity_id == job_uuid)
            .order_by(AuditLog.created_at.asc())
            .limit(limit)
            .all()
            )

        return [
            {
                "id": str(audit.id),
                "action": audit.action,
                "entity_type": audit.entity_type,
                "entity_id": str(audit.entity_id),
                "user_id": str(audit.user_id) if audit.user_id else None,
                "ip_address": audit.ip_address,
                "user_agent": audit.user_agent,
                "created_at": audit.created_at,
                }
                for audit in rows
                ]
