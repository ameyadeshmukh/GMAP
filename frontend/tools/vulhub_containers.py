import os
import sys
import subprocess

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)
VULHUB_DIR = os.path.join(BASE_DIR, "vulhub")
sys.path.append(BASE_DIR)
from metasetup.vulhub_catalog import VULHUB_EXPLOIT_CATALOG

def get_vulhub_scenarios():
    scenarios = {}

    for rule in VULHUB_EXPLOIT_CATALOG:
        path = resolve_scenario_path(rule)

        # only show valid scenarios
        if not path:
            continue

        label = rule.scenario
        if rule.cve:
            label += f" ({rule.cve})"

        scenarios[label] = rule

    return scenarios

def is_vulhub_running(rule):
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True
        )

        containers = result.stdout.lower()

        # match by scenario folder name
        keyword = rule.scenario.split("/")[-1].lower()

        return keyword in containers

    except Exception:
        return False

# matches scenarios from our vulhub catalog to the actual vulhub/ github directory
def resolve_scenario_path(rule):
    if not os.path.exists(VULHUB_DIR ):
        return None

    scenario = rule.scenario.lower()
    cve = (rule.cve or "").lower()

    # 1. FULL exact match anywhere in path
    exact = os.path.join(VULHUB_DIR , *rule.scenario.split("/"))
    if os.path.exists(exact):
        return exact

    # 2. Deep search (fixes ALL your current issues)
    for root, dirs, files in os.walk(VULHUB_DIR ):

        root_l = root.lower()

        # skip noise dirs
        if any(x in root_l for x in [".git", ".github", ".claude"]):
            continue

        # match full scenario string anywhere
        if scenario in root_l:
            return root

        # match CVE anywhere in path
        if cve and cve in root_l:
            return root

        # fallback: last segment match
        folder = os.path.basename(root_l)
        target = rule.scenario.split("/")[-1].lower().replace(".", "")

        if target in folder.replace(".", ""):
            return root

    return None

def launch_vulhub(rule):
    scenario_path = resolve_scenario_path(rule)

    if not scenario_path:
        return False, "Scenario not found"

    # replace if port is in use already
    if rule.port:
        stop_conflicting_containers(rule.port)

    for p in [80, 443, 8080, 3000, 3306]:
        stop_conflicting_containers(p)

    if is_vulhub_running(rule):
        return True, f"Already running: {scenario_path}"

    subprocess.Popen(
        ["docker", "compose", "up", "-d"],
        cwd=scenario_path
    )

    return True, f"Started: {scenario_path}"

def stop_conflicting_containers(port):
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.ID}} {{.Ports}}"],
        capture_output=True,
        text=True
    )

    for line in result.stdout.splitlines():
        if f":{port}->" in line:
            container_id = line.split()[0]
            subprocess.run(["docker", "stop", container_id])