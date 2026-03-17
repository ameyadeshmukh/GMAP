import time
from celery_app import app
from ingestion import JOB_STORE
from jobs.job_states import JobState

# TODO need to setup DB to get persistent jobs

@app.task
def run_nmap(target_ip, job_id=None):
    job = JOB_STORE.get(job_id)
    if job:
        job.transition_state(JobState.STARTED)

    print(f"Scanning {target_ip}...")
    time.sleep(2)
    result = {"tool": "nmap", "open_ports": [80, 443, 8080]}

    if job:
        job.results = result
        job.transition_state(JobState.SUCCESS)
    return result

@app.task
def run_nuclei(target_url, job_id=None):
    job = JOB_STORE.get(job_id)
    if job:
        job.transition_state(JobState.STARTED)

    print(f"Running nuclei against {target_url}...")
    time.sleep(3)
    result = {"tool": "nuclei", "cves_found": ["Example CVE"]}

    if job:
        job.results = result
        job.transition_state(JobState.SUCCESS)
    return result

@app.task
def parse_results(results):
    print(f"Parsing results from scan...")
    time.sleep(1)
    return {"status": "parsed"}

