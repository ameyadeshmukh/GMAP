from validation import validate_target
# from tasks import run_nmap, run_nuclei
from jobs.job import Job
from jobs.job_states import JobState

# temp in-memory storage (TODO replace with DB model)
JOB_STORE = {}

# used for creating job, validating target URL, and queuing preliminary scans
def ingest_target(target_url: str):
    from tasks import run_nmap, run_nuclei

    # validate URL
    is_valid, reason = validate_target(target_url)
    if not is_valid:
        return {
            "status": "rejected",
            "reason": reason
        }

    # normalize URL to avoid duplicates- GitHub repo URLs are not case-sensitive
    normalized_url = target_url.strip().lower()

    # create job for target URL
    job = Job(target_url=normalized_url)

    # store (TODO replace with your DB model)
    JOB_STORE[job.id] = job

    job.transition_state(JobState.RECEIVED) # change job state

    # initial scans for all jobs
    task1 = run_nmap.delay(normalized_url, job.id)   # queue celery task 1 (nmap)
    task2 = run_nuclei.delay(normalized_url, job.id)    # queue celery task 2 (nuclei)

    # add Celery task IDs to job
    job.celery_task_ids.append(task1.id)
    job.celery_task_ids.append(task2.id)

    return {
        "status": "accepted",
        "job_id": job.id,
        "job_state": job.state,
        "celery_task_id1": task1.id,
        "celery_task_id2": task2.id
    }