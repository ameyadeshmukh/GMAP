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
    # SSTI
    "flask/ssti",
    "jira/CVE-2019-11581",

    # Info Disclosure / Path Traversal
    "grafana/CVE-2021-43798",

    # RCE - GitLab
    "gitlab/CVE-2021-22205",

    # RCE - Jenkins
    "jenkins/CVE-2018-1000861",
    "jenkins/CVE-2017-1000353",

    # RCE - Tomcat
    "tomcat/CVE-2017-12615",
    "tomcat/CVE-2020-1938",

    # RCE - WebLogic
    "weblogic/CVE-2020-14882",
    "weblogic/CVE-2018-2628",
    "weblogic/CVE-2018-2894",

    # RCE - JBoss
    "jboss/CVE-2017-12149",
    "jboss/CVE-2017-7504",

    # CMS - Drupal
    "drupal/CVE-2018-7600",
    "drupal/CVE-2019-6340",

    # CMS - WordPress
    "wordpress/pwnscriptum",

    # SQL Injection / RCE - ThinkPHP
    "thinkphp/2-rce",
    "thinkphp/5-rce",
    "thinkphp/5.0.23-rce",

    # Auth Bypass - Shiro
    "shiro/CVE-2016-4437",
    "shiro/CVE-2020-1957",

    # RCE - Spring
    "spring/CVE-2022-22947",
    "spring/CVE-2022-22965",
    "spring/CVE-2018-1273",

    # RCE - Laravel
    "laravel/CVE-2021-3129",

    # RCE - Confluence
    "confluence/CVE-2021-26084",
    "confluence/CVE-2022-26134",
    "confluence/CVE-2023-22527",

    # Info Disclosure - Kibana
    "kibana/CVE-2019-7609",

    # RCE - Elasticsearch
    "elasticsearch/CVE-2014-3120",
    "elasticsearch/CVE-2015-1427",

    # Auth Bypass - Nacos
    "nacos/CVE-2021-29441",

    # RCE - Nexus
    "nexus/CVE-2019-7238",
    "nexus/CVE-2020-10199",

    # RCE - ActiveMQ
    "activemq/CVE-2023-46604",
    "activemq/CVE-2016-3088",

    # XXE / RCE - Solr
    "solr/CVE-2017-12629-XXE",
    "solr/CVE-2019-17558",
    "solr/CVE-2017-12629-RCE",

    # Deserialization - Fastjson
    "fastjson/1.2.24-rce",
    "fastjson/1.2.47-rce",

    # Deserialization - Jackson
    "jackson/CVE-2017-7525",

    # Path Traversal / RCE - Apache HTTPD
    "httpd/CVE-2021-41773",
    "httpd/CVE-2021-42013",
    "httpd/CVE-2021-40438",

    # Django
    "django/CVE-2019-14234",
    "django/CVE-2021-35042",
]

def stop_container(path):
    cwd = os.path.join(VULHUB, path)
    subprocess.run(["docker", "compose", "down", "-v"], cwd=cwd)

def get_container_ip(path):
    cwd = os.path.join(VULHUB, path)
    result = subprocess.run(
        ["docker", "compose", "ps", "-q"],
        cwd=cwd, capture_output=True, text=True
    )
    container_ids = [c for c in result.stdout.strip().split("\n") if c.strip()]
    
    for container_id in container_ids:
        inspect = subprocess.run(
            ["docker", "inspect", container_id],
            capture_output=True, text=True
        )
        data = json.loads(inspect.stdout)
        # check all networks not just the default
        networks = data[0]["NetworkSettings"]["Networks"]
        for net in networks.values():
            ip = net.get("IPAddress", "")
            if ip:
                return ip
    return None

def start_container(path):
    cwd = os.path.join(VULHUB, path)
    subprocess.run(["docker", "compose", "up", "-d"], cwd=cwd, check=True)
    # wait longer and retry IP check
    for _ in range(12):  # up to 60s
        time.sleep(5)
        ip = get_container_ip(path)
        if ip:
            return
    print("  WARNING: container may not be ready")

def submit_and_wait(target_url, timeout=600):
    try:
        resp = requests.post(f"{API}/targets", json={"target_url": target_url}, timeout=10)
        resp.raise_for_status()
        job_id = resp.json().get("job_id")
    except Exception as e:
        print(f"  Submit failed: {e}")
        return {"error": str(e)}
    
    print(f"  Job ID: {job_id}")
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{API}/jobs/{job_id}", timeout=10)
            status = r.json().get("status")
            print(f"  status: {status}")
            if status in ("completed", "failed", "error"):
                return r.json()
        except Exception as e:
            print(f"  Poll error: {e}")
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