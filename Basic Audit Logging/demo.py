import uuid
import time

from sqlalchemy.orm import Session
from db import SessionLocal
from audit_service import audit_write

def main():
    job_id = str(uuid.uuid4())
    db: Session = SessionLocal()
    try:
        # Simulated events to serve as examples for how the basic audit logging works and gets stored into the created database on docker
        audit_write(db, job_id=job_id, event_type="JOB_CREATED", message="Job created for repo file scan.", meta={"target": "example/repo"})
        audit_write(db, job_id=job_id, event_type="JOB_STARTED", message="Worker started agent workflow.")
        db.commit()

        audit_write(db, job_id=job_id, event_type="STEP_STARTED", message="Perception: ingest repo.", meta={"step": 1})
        db.commit()
        time.sleep(0.2)

        audit_write(db, job_id=job_id, event_type="TOOL_STARTED", message="Tool started: semgrep.", meta={"tool": "semgrep", "args": {"config": "p/ci"}})
        db.commit()
        time.sleep(0.2)

        audit_write(db, job_id=job_id, event_type="TOOL_FINISHED", message="Tool finished: semgrep.", meta={"tool": "semgrep", "findings": 2})
        audit_write(db, job_id=job_id, event_type="DECISION", message="Agent chose to validate the highest confidence finding.", meta={"finding_id": "F-001"})
        db.commit()
        time.sleep(0.2)

        audit_write(db, job_id=job_id, event_type="JOB_FINISHED", message="Job finished successfully.", meta={"status": "COMPLETED"})
        db.commit()

        print(job_id) 
    finally:
        db.close()

if __name__ == "__main__":
    main()