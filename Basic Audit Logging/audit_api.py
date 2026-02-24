import uuid
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from db import get_db
from audit_models import AuditLog

router = APIRouter(prefix="/audit", tags=["audit"])

@router.get("/jobs/{job_id}")
def audit_list_for_job(
    job_id: str,
    limit: int = Query(default=500, ge=1, le=2000),
    db: Session = Depends(get_db),
):
    try:
        job_uuid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="job_id must be a UUID")

    rows = (
        db.query(AuditLog)
        .filter(AuditLog.job_id == job_uuid)
        .order_by(AuditLog.created_at.asc())
        .limit(limit)
        .all()
    )
 
    return [ # current fields that are being used 
        {
            "created_at": r.created_at,
            "level": r.level,
            "event_type": r.event_type,
            "message": r.message,
            "meta": r.meta,
        }
        for r in rows
    ]