from typing import Any, Dict, Optional
from sqlalchemy.orm import Session
from backend.models import AuditLog

ALLOWED_LEVELS = {"INFO", "WARN", "ERROR"}

def audit_write(
    db: Session,
    *,
    job_id: str,
    action: str,
    entity_type: str = "job",
    user_id: Optional[str] = None,
):
    db.add(AuditLog(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),  # or real tenant
        user_id=uuid.UUID(user_id) if user_id else uuid.uuid4(),
        entity_type=entity_type,
        entity_id=uuid.UUID(job_id),
        action=action,
        before_hash="",
        after_hash="",
        ip_address="127.0.0.1",
        user_agent="system",
    ))
