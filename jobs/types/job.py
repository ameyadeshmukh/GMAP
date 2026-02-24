import uuid
from datetime import datetime

from job_states import JobState, ALLOWED_TRANSITIONS


class Job:
    def __init__(self, target_url: str, scan_type: str = "full"):
        self.id = str(uuid.uuid4())
        self.target_url = target_url
        self.scan_type = scan_type

        self.state = JobState.CREATED
        self.created_at = datetime.utcnow()

        self.results = None
        self.errors = None

    def transition_state(self, new_state: JobState):
        if new_state not in ALLOWED_TRANSITIONS[self.state]:
            raise ValueError(
                f"Invalid transition: {self.state} → {new_state}"
            )
        self.state = new_state

    def __repr__(self):
        return (f"Job(id={self.id}, state={self.state}), "
                f"scan type: {self.created_at}, created at: {self.created_at}, repo url: {self.target_url}")