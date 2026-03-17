import time
from celery_app import app
from store import JOB_STORE
from jobs.job_states import JobState

# TODO: Replace JOB_STORE references with DB lookups once persistent storage is added.


@app.task
def run_nmap(target, job_id=None):
    job = JOB_STORE.get(job_id)
    if job:
        job.transition_state(JobState.STARTED)

    print(f"[nmap] Scanning {target}...")
    time.sleep(2)
    result = {"tool": "nmap", "open_ports": [80, 443, 8080]}

    if job:
        job.results = result
        job.transition_state(JobState.SUCCESS)
    return result


@app.task
def run_nuclei(target, job_id=None):
    job = JOB_STORE.get(job_id)
    if job:
        job.transition_state(JobState.STARTED)

    print(f"[nuclei] Scanning {target}...")
    time.sleep(3)
    result = {"tool": "nuclei", "cves_found": ["CVE-XXXX-XXXXX"]}

    if job:
        job.results = result
        job.transition_state(JobState.SUCCESS)
    return result
