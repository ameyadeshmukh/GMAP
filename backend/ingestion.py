import uuid
from datetime import datetime, UTC

from validation import validate_target
from tasks import run_nmap, run_nuclei

# temp in-memory storage (TODO replace with DB model)
TARGET_STORE = {}

def ingest_target(target_url: str):
    # validate URL
    is_valid, reason = validate_target(target_url)
    if not is_valid:
        return {
            "status": "rejected",
            "reason": reason
        }

    # normalize URL to avoid duplicates- GitHub repo URLs are not case-sensitive
    normalized_url = target_url.strip().lower()

    # store (TODO replace with your DB model)
    target_id = str(uuid.uuid4())

    TARGET_STORE[target_id] = {
        "id": target_id,
        "url": normalized_url,
        "status": "validated",
        "created_at": str(datetime.now(UTC))
    }

    # trigger existing Celery tasks (nmap and nuclei- might want to change which tasks are triggered initially here)
    nmap_task = run_nmap.delay(normalized_url)
    nuclei_task = run_nuclei.delay(normalized_url)

    # response
    return {
        "status": "accepted",
        "target_id": target_id,
        "target_url": normalized_url,
        "tasks": {
            "nmap_task_id": nmap_task.id,
            "nuclei_task_id": nuclei_task.id
        }
    }