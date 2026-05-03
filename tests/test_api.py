import pytest
from fastapi.testclient import TestClient
from backend.api import app


client = TestClient(app)

def test_valid_scan():
    response = client.post("/scan", json={
        "scan_type": "nmap",
        "open_ports": [22, 80],
        "vulnerabilities": [
            {"cve": "CVE-2024-1234", "severity": "high"}
        ]
    })

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "validated"
    assert data["scan_type"] == "nmap"
    assert data["ports_count"] == 2
    assert data["vuln_count"] == 1

def test_invalid_ports_type():
    response = client.post("/scan", json={
        "scan_type": "nmap",
        "open_ports": ["bad_data"],
        "vulnerabilities": []
    })

    assert response.status_code == 422

def test_missing_scan_type():
    response = client.post("/scan", json={
        "open_ports": [22],
        "vulnerabilities": []
    })

    assert response.status_code == 422


# EMPTY JSON TEST
def test_empty_json():
    response = client.post("/scan", json={})
    assert response.status_code == 422


# EXTRA FIELD TEST
def test_extra_field():
    response = client.post("/scan", json={
        "scan_type": "nmap",
        "open_ports": [22],
        "vulnerabilities": [],
        "unexpected": "data"
    })

   
    assert response.status_code == 200


# LARGE PAYLOAD TEST
def test_large_payload():
    large_ports = list(range(1, 1000))

    response = client.post("/scan", json={
        "scan_type": "nmap",
        "open_ports": large_ports,
        "vulnerabilities": []
    })

    assert response.status_code == 200


# INVALID VULNERABILITY STRUCTURE
def test_invalid_vulnerability():
    response = client.post("/scan", json={
        "scan_type": "nmap",
        "open_ports": [22],
        "vulnerabilities": [
            {"cve": 123, "severity": "high"}  # cve should be string
        ]
    })

    assert response.status_code == 422