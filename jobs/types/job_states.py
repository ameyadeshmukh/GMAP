from enum import Enum

class JobState(str, Enum):
    CREATED = "CREATED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED_SUCCESS = "COMPLETED_SUCCESS"
    COMPLETED_FAILURE = "COMPLETED_FAILURE"


# allowed transitions between states
ALLOWED_TRANSITIONS = {
    JobState.CREATED: [JobState.QUEUED],
    JobState.QUEUED: [JobState.RUNNING],
    JobState.RUNNING: [JobState.COMPLETED_SUCCESS, JobState.COMPLETED_FAILURE],
    JobState.COMPLETED_SUCCESS: [],
    JobState.COMPLETED_FAILURE: [],
}