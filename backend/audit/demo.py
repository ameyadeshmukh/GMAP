"""
Standalone script to write sample audit events to the database.
Run from the backend/ directory: python -m audit.demo
"""
import uuid
import time
from backend.db import SessionLocal
from .service import audit_write


def main():
    job_id = str(uuid.uuid4())
    db = SessionLocal()
    try:
        audit_write(db, job_id=job_id, event_type="JOB_CREATED", message="Job created for scan.", meta={"target": "192.168.1.1"})
        audit_write(db, job_id=job_id, event_type="JOB_STARTED", message="Worker started agent workflow.")
        db.commit()

        audit_write(db, job_id=job_id, event_type="TOOL_STARTED", message="Tool started: nmap.", meta={"tool": "nmap"})
        db.commit()
        time.sleep(0.2)

        audit_write(db, job_id=job_id, event_type="TOOL_FINISHED", message="Tool finished: nmap.", meta={"tool": "nmap", "open_ports": [80, 443]})
        audit_write(db, job_id=job_id, event_type="DECISION", message="Agent chose to run nuclei on open ports.", meta={"ports": [80, 443]})
        db.commit()
        time.sleep(0.2)

        audit_write(db, job_id=job_id, event_type="JOB_FINISHED", message="Job finished successfully.", meta={"status": "completed"})
        db.commit()

        print(f"Demo audit log written for job_id: {job_id}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
