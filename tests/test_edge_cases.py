import pytest
from backend.tasks import run_scan

#Edge case testing
#Empty JSON
def test_empty_json():
    with pytest.raises(ValueError):
        run_scan.apply(args=[{}]).get()

#Large payload
def test_large_payload():
    payload = {
        "scan_type": "nmap",
        "data": ["x" * 1000] * 10000
    }

    result = run_scan.apply(args=[payload]).get(timeout=10)

    assert result["status"] == "completed"

#Nested JSON
def test_nested_json():
    payload = {
        "scan_type": "nmap",
        "data": {"a": {"b": {"c": "value"}}}
    }

    result = run_scan.apply(args=[payload]).get()

    assert result["status"] == "completed"

#Invalid structure
def test_invalid_structure():
    payload = {"random": "data"}

    with pytest.raises(ValueError):
        run_scan.apply(args=[payload]).get()