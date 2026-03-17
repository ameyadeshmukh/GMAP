from validation import validate_target
from tasks import run_nmap, run_nuclei
from store import JOB_STORE
from jobs.job import Job
from jobs.job_states import JobState


def ingest_target(target_url: str):
    is_valid, reason = validate_target(target_url)
    if not is_valid:
        return {"status": "rejected", "reason": reason}

    normalized = target_url.strip().lower()

    job = Job(target_url=normalized)
    JOB_STORE[job.id] = job
    job.transition_state(JobState.RECEIVED)

    # TODO: Replace with a sequential Celery chain once the LangGraph agent is in place.
    # Intended order: nmap → agent decision → httpx → agent decision → nuclei
    task1 = run_nmap.delay(normalized, job.id)
    task2 = run_nuclei.delay(normalized, job.id)

    job.celery_task_ids.extend([task1.id, task2.id])

    return {
        "status": "accepted",
        "job_id": job.id,
        "job_state": job.state,
        "celery_task_ids": job.celery_task_ids,
    }