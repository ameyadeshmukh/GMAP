import time
from backend.db import get_db
from backend.models import ReviewRequest, JobExecution

REVIEW_TIMEOUT = 600
POLL_INTERVAL = 3

CVE_TO_MSF = {
    "cve-2013-2251": {
        "module": "exploit/multi/http/struts_default_action_mapper",
        "notes": "Struts2 DefaultActionMapper OGNL injection",
    },
    "cve-2017-5638": {
        "module": "exploit/multi/http/struts2_content_type_ognl",
        "notes": "Struts2 Content-Type OGNL injection",
    },
    "cve-2023-46604": {
        "module": "exploit/multi/misc/apache_activemq_rce_cve_2023_46604",
        "notes": "ActiveMQ ClassInfo RCE",
    },
    "cve-2018-7600": {
        "module": "exploit/unix/webapp/drupal_drupalgeddon2",
        "notes": "Drupalgeddon2 RCE",
    },
    "cve-2007-2447": {
        "module": "exploit/multi/samba/usermap_script",
        "notes": "Samba username map script RCE",
    },
}


def _map_vulns_to_modules(vulnerabilities):
    """Map confirmed vulnerabilities to metasploit modules."""
    suggestions = []
    seen_modules = set()

    for vuln in vulnerabilities:
        cve = (vuln.get("cve_id") or vuln.get("cve") or "").lower()
        mapping = CVE_TO_MSF.get(cve)

        if not mapping or not mapping.get("module"):
            continue

        module = mapping["module"]
        if module in seen_modules:
            continue
        seen_modules.add(module)

        suggestions.append({
            "cve": cve,
            "severity": vuln.get("severity", "unknown"),
            "module": module,
            "notes": mapping["notes"],
            "confirmed_url": vuln.get("url", ""),
            "template_id": vuln.get("template_id", ""),
        })

    return suggestions


def review(state):
    job_id = state["job_id"]
    vulnerabilities = state.get("vulnerabilities", [])

    exploit_suggestions = _map_vulns_to_modules(vulnerabilities)
    msf_modules = [s["module"] for s in exploit_suggestions]


    with get_db() as db:
        job_exec = db.query(JobExecution).filter_by(id=job_id).first()
        if job_exec:
            job_exec.status = "requires_review"

        existing = db.query(ReviewRequest).filter_by(job_execution_id=job_id).first()
        if existing:
            existing.decision = None
            existing.vulnerabilities = vulnerabilities
            existing.msf_modules = msf_modules 
            #existing.exploit_suggestions = exploit_suggestions
        else:
            db.add(ReviewRequest(
                job_execution_id=job_id,
                vulnerabilities=vulnerabilities,
                msf_modules=msf_modules, 
                #exploit_suggestions=exploit_suggestions,
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
                return {
                    **state,
                    "human_decision": decision,
                    "awaiting_human": False,
                    "msf_modules": msf_modules, # 
                }
        time.sleep(POLL_INTERVAL)

    # Timed out
    with get_db() as db:
        job_exec = db.query(JobExecution).filter_by(id=job_id).first()
        if job_exec:
            job_exec.status = "running"

    return {
        **state,
        "human_decision": "skip",
        "awaiting_human": False,
        "msf_modules": msf_modules,
    }