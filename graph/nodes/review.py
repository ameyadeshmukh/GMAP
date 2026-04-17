import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "backend"))

from db import get_db
from models import ReviewRequest, JobExecution

REVIEW_TIMEOUT = 600  # 10 minutes
POLL_INTERVAL = 3


def review(state):
    """
    Pauses execution to let the human review vulnerabilities before exploitation.
    Sets job status to 'requires_review', writes findings to DB, then polls
    for a decision (approve / skip / abort). Times out after 10 minutes (→ skip).
    """
    job_id = state["job_id"]

    with get_db() as db:
        job_exec = db.query(JobExecution).filter_by(id=job_id).first()
        if job_exec:
            job_exec.status = "requires_review"

        existing = db.query(ReviewRequest).filter_by(job_execution_id=job_id).first()
        if existing:
            existing.decision = None
            existing.vulnerabilities = state.get("vulnerabilities", [])
            existing.msf_modules = state.get("msf_modules", [])
        else:
            db.add(ReviewRequest(
                job_execution_id=job_id,
                vulnerabilities=state.get("vulnerabilities", []),
                msf_modules=state.get("msf_modules", []),
            ))

    deadline = time.time() + REVIEW_TIMEOUT
    while time.time() < deadline:
        with get_db() as db:
            req = db.query(ReviewRequest).filter_by(job_execution_id=job_id).first()
            if req and req.decision:
                decision = req.decision
                job_exec = db.query(JobExecution).filter_by(id=job_id).first()
                if job_exec:
                    job_exec.status = "running"
                return {**state, "human_decision": decision, "awaiting_human": False}
        time.sleep(POLL_INTERVAL)

    # Timed out — default to skip
    with get_db() as db:
        job_exec = db.query(JobExecution).filter_by(id=job_id).first()
        if job_exec:
            job_exec.status = "running"

    return {**state, "human_decision": "skip", "awaiting_human": False}
