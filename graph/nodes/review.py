import time
from backend.db import get_db
from backend.models import ReviewRequest, JobExecution


def _enrich_vulnerabilities(vulnerabilities):
    enriched = []
    for vuln in vulnerabilities:
        cve = vuln.get("cve_id") or vuln.get("template_id", "")
        nvd_link = None
        if cve and cve.upper().startswith("CVE-"):
            nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve.upper()}"
        enriched.append({**vuln, "nvd_link": nvd_link})
    return enriched


def review(state):
    job_id = state["job_id"]
    vulnerabilities = state.get("vulnerabilities", [])
    log = state.get("action_log", [])

    enriched_vulns = _enrich_vulnerabilities(vulnerabilities)
    log.append(f"[REVIEW] enriched {len(enriched_vulns)} vulnerabilities for display")

    # write to DB and immediately return abort — no waiting
    with get_db() as db:
        job_exec = db.query(JobExecution).filter_by(id=job_id).first()
        if job_exec:
            job_exec.status = "running"  # don't set requires_review, go straight through

        existing = db.query(ReviewRequest).filter_by(job_execution_id=job_id).first()
        if existing:
            existing.decision = "abort"
            existing.vulnerabilities = enriched_vulns
            existing.msf_modules = []
        else:
            db.add(ReviewRequest(
                job_execution_id=job_id,
                vulnerabilities=enriched_vulns,
                msf_modules=[],
                decision="abort",
            ))

    return {
        **state,
        "human_decision": "abort",
        "awaiting_human": False,
        "action_log": log,
    }