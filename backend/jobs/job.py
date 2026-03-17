import uuid
from datetime import datetime, UTC

from .job_states import JobState, ALLOWED_TRANSITIONS


class Job:
    def __init__(self, target_url: str):
        self.id = str(uuid.uuid4())
        self.target_url = target_url
        self.state = JobState.PENDING
        self.created_at = datetime.now(UTC)
        self.updated_at = self.created_at
        self.celery_task_ids = []
        self.results = {}
        self.errors = {}

    def transition_state(self, new_state: JobState):
        if new_state not in ALLOWED_TRANSITIONS[self.state]:
            raise ValueError(
                f"Invalid transition: {self.state} → {new_state}"
            )
        self.state = new_state
        self.updated_at = datetime.now(UTC)

    def __repr__(self):
        return (
            f"Job(id={self.id}, "
            f"state={self.state}, "
            f"created_at={self.created_at}, "
            f"target_url={self.target_url})"
        )