from celery import Celery

app = Celery(
    'scanner',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/0',
    include=['backend.tasks']
)

app.conf.update(
    task_track_started=True,
    result_expires=3600,
)