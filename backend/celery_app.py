from celery import Celery

app = Celery(
    'scanner',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/0',
    include=['tasks']
)

app.conf.update(
    task_track_started=True,
    result_expires=3600,
)

celery_app = Celery(
    "gmap",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)

celery_app.conf.task_routes = {
    "tasks.*": {"queue": "default"}
}