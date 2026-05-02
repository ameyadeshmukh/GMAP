# batch_test.py
import subprocess
import requests
import time
import json
import os

API = "http://localhost:8000"
VULHUB = "/root/vulhub"
RESULTS_DIR = "./batch_results"
os.makedirs(RESULTS_DIR, exist_ok=True)

TARGETS = [
    # Auth Bypass
    "confluence/CVE-2023-22515",

    # Backdoor
    "php/8.1-backdoor",

    # CMS
    "drupal/CVE-2018-7600",

    # Database
    "h2database/CVE-2021-42392",

    # Deserialization
    "shiro/CVE-2016-4437",

    # DoS
    "openssl/CVE-2022-0778",

    # Environment Injection
    "cgi/CVE-2016-5385",

    # Expression Injection
    "confluence/CVE-2022-26134",

    # File Deletion
    "discuz/x3.4-arbitrary-file-deletion",

    # File Upload
    "tomcat/CVE-2017-12615",

    # Framework
    "laravel/CVE-2021-3129",

    # Hard Coding
    "influxdb/CVE-2019-20933",

    # Info Disclosure
    "owncloud/CVE-2023-49103",

    # LLM
    "gradio/CVE-2024-1561",

    # Message Queue
    "activemq/CVE-2023-46604",

    # Path Traversal
    "httpd/CVE-2021-41773",

    # Privilege Escalation
    "saltstack/CVE-2020-11651",

    # RCE
    "log4j/CVE-2021-44228",

    # SQL Injection
    "cacti/CVE-2023-39361",

    # SSRF
    "adminer/CVE-2021-21311",

    # SSTI
    "flask/ssti",

    # Webserver
    "glassfish/CVE-2017-1000028",

    # XSS
    "django/CVE-2017-12794",

    # XXE
    "solr/CVE-2017-12629-XXE",
]

def start_container(path):
    cwd = os.path.join(VULHUB, path)
    subprocess.run(["docker", "compose", "up", "-d"], cwd=cwd, check=True)
    time.sleep(15)

def stop_container(path):
    cwd = os.path.join(VULHUB, path)
    subprocess.run(["docker", "compose", "down", "-v"], cwd=cwd)

def get_container_ip(path):
    cwd = os.path.join(VULHUB, path)
    result = subprocess.run(
        ["docker", "compose", "ps", "-q"],
        cwd=cwd, capture_output=True, text=True
    )
    # grab first container id
    container_id = result.stdout.strip().split("\n")[0]
    inspect = subprocess.run(
        ["docker", "inspect", container_id],
        capture_output=True, text=True
    )
    data = json.loads(inspect.stdout)
    return data[0]["NetworkSettings"]["IPAddress"]

def submit_and_wait(target_url, timeout=600):
    resp = requests.post(f"{API}/targets", json={"target_url": target_url})
    job_id = resp.json().get("job_id")
    print(f"  Job ID: {job_id}")

    start = time.time()
    while time.time() - start < timeout:
        r = requests.get(f"{API}/jobs/{job_id}")
        status = r.json().get("status")
        print(f"  status: {status}")
        if status in ("completed", "failed", "error"):
            return r.json()
        time.sleep(15)

    return {"error": "timeout"}

for path in TARGETS:
    name = path.replace("/", "-")
    print(f"\n=== Testing {name} ===")

    try:
        start_container(path)
        ip = get_container_ip(path)
        print(f"  Container IP: {ip}")

        result = submit_and_wait(ip)

        with open(f"{RESULTS_DIR}/{name}.json", "w") as f:
            json.dump(result, f, indent=2)

        print(f"  Saved to {RESULTS_DIR}/{name}.json")

    except Exception as e:
        print(f"  ERROR: {e}")

    finally:
        stop_container(path)

print("\n=== Batch complete ===")
print(f"Results saved to {RESULTS_DIR}/")