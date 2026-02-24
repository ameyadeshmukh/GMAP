from typing import Any, Dict, Optional
from sqlalchemy.orm import Session
from audit_models import AuditLog

# Stucture of each entry/ levels only INFO is being used but having warn/error later on is needed to ensure everything is running correctly 
ALLOWED_LEVELS = {"INFO", "WARN", "ERROR"}

def audit_write(
    db: Session,
    *,
    job_id: str,
    event_type: str,
    message: str,
    level: str = "INFO",
    meta: Optional[Dict[str, Any]] = None,
) -> None:
    lvl = level.upper().strip()
    if lvl not in ALLOWED_LEVELS:
        lvl = "INFO"

    db.add(AuditLog(
        job_id=job_id,
        level=lvl,
        event_type=event_type,
        message=message,
        meta=meta or {},
    ))
  