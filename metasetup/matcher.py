from typing import Optional
from vulhub_catalog import VULHUB_EXPLOIT_CATALOG

# Matcher for the Agentic AI to match the results based on what is found in the inital discovery.
def _eq(a, b):
    if a is None or b is None:
        return False
    return str(a).lower() == str(b).lower()

def match_rule(result: dict) -> Optional[object]:
    best = None
    best_score = -1

    for rule in VULHUB_EXPLOIT_CATALOG:
        score = 0

        # Must be Vulhub in this case since the catalog is based on vulhhub exploits
        if result.get("source_lab") != "vulhub":
            continue

        score += 20

        # Scenario match 
        if _eq(result.get("scenario"), rule.scenario):
            score += 100

        # CVE match
        if rule.cve and _eq(result.get("cve"), rule.cve):
            score += 80

        # Product
        if rule.product and _eq(result.get("product"), rule.product):
            score += 30

        # Version
        if rule.version and _eq(result.get("version"), rule.version):
            score += 30

        # Service
        if rule.service and _eq(result.get("service"), rule.service):
            score += 20

        # Port
        if rule.port and result.get("port") == rule.port:
            score += 10

        score += rule.rank

        if score > best_score:
            best = rule
            best_score = score

    return best