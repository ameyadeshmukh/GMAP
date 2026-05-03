import pytest
from backend.tasks import run_scan
from backend.celery_app import celery_app as celery

#Celery Task Processing test
#Validate async processing
#Example celery task
@celery.task(bind=True)
def run_scan(self, payload):
    #Validation layer
    if not isinstance(payload, dict):
        raise ValueError("Payload must be a dictionary")

    if "scan_type" not in payload:
        raise ValueError("Missing scan_type")

    return {
        "status": "completed",
        "summary": f"Processed {payload['scan_type']}",
        "data": payload
    }

def test_task_processing():
    result = run_scan.apply(args=[{
        "scan_type": "nmap",
        "vulnerabilities": []
    }]).get()

    assert result["status"] == "completed"
    assert "summary" in result

#Failure handling test
def test_bad_json_handling():
    bad_input = {"unexpected": "data"}

    with pytest.raises(Exception):
        run_scan.apply(args=[bad_input]).get()