from enum import Enum

class JobState(str, Enum):
    PENDING = "PENDING"    # created
    RECEIVED = "RECEIVED"  # queued
    STARTED = "STARTED"    # running
    SUCCESS = "SUCCESS"    # competed successfully
    FAILURE = "FAILURE"    # completed failure


# allowed transitions between states
ALLOWED_TRANSITIONS = {
    JobState.PENDING: [JobState.RECEIVED],
    JobState.RECEIVED: [JobState.STARTED],
    JobState.STARTED: [JobState.SUCCESS, JobState.FAILURE],
    JobState.SUCCESS: [],
    JobState.FAILURE: [],
}