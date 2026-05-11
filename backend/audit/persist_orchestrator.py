from typing import Any, Dict, Optional
from backend.db import SessionLocal
from backend.audit.service import audit_write


def persist_orchestrator_output(
    *,
    job_id: str,
    phase: str,
    payload: Dict[str, Any],
    raw_llm_text: Optional[str] = None,
) -> None:
    db = SessionLocal()
    try:
        audit_write(
            db,
            job_id=job_id,
            event_type="DECISION",
            message=payload.get("reasoning") or f"Decision: {payload.get('decision')}",
            level="INFO",
            meta={
                "phase": phase,
                "decision": payload.get("decision"),
                "retry_command": payload.get("retry_command"),
                "correlations": payload.get("correlations", []),
                "full_payload": payload,
                "raw_llm_text": raw_llm_text,
            },
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()