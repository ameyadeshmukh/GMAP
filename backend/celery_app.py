import os

from celery import Celery


REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
if REDIS_URL.startswith("rediss://") and "ssl_cert_reqs=" not in REDIS_URL:
    separator = "&" if "?" in REDIS_URL else "?"
    REDIS_URL = f"{REDIS_URL}{separator}ssl_cert_reqs=CERT_REQUIRED"

app = Celery(
    'scanner',
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=['backend.tasks']
)

app.conf.update(
    task_track_started=True,
    result_expires=3600,
)