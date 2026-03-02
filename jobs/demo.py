import time
from job import Job
from job_states import JobState


def simulate_job_lifecycle():

    # simulate successful
    print("\n--- JOB 1: SIMULATE SUCCESS ---\n")
    job1 = Job(target_url="https://example.com", scan_type="full")
    print("Created job id:", job1.id)

    time.sleep(1)
    job1.transition_state(JobState.RECEIVED)
    print("Received job 1")

    time.sleep(1)
    job1.transition_state(JobState.STARTED)
    print("Started job 1")

    time.sleep(2)   # simulate work

    job1.results = {"issues_found": 3}
    job1.transition_state(JobState.SUCCESS)
    print("Success:", job1, "\n")

    # simulate failure
    print("\n--- JOB 2: SIMULATE FAILURE ---\n")
    job2 = Job(target_url="https://example.com", scan_type="partial")
    print("Created job id:", job1.id)

    time.sleep(1)
    job2.transition_state(JobState.RECEIVED)
    print("Received job 2")

    time.sleep(1)
    job2.transition_state(JobState.STARTED)
    print("Started job 2")

    time.sleep(2)   # simulate work

    job2.results = {"issues_found": 3}
    job2.transition_state(JobState.FAILURE)
    print("Failure:", job2)


if __name__ == "__main__":
    simulate_job_lifecycle()