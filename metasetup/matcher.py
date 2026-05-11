from typing import Optional
from metasetup.vulhub_catalog import VULHUB_EXPLOIT_CATALOG

# Matcher for the Agentic AI to match the results based on what is found in the inital discovery.
def _eq(a, b):
    if a is None or b is None:
        return False
    return str(a).lower() == str(b).lower()


def _contains(a, b):
    if a is None or b is None:
        return False
    return str(b).lower() in str(a).lower()


def match_rule(result: dict) -> Optional[object]:
    best = None
    best_score = -1

    for rule in VULHUB_EXPLOIT_CATALOG:
        if result.get("source_lab") != "vulhub":
            continue

        score = 0
        evidence_count = 0
    # Scenario
        if _eq(result.get("scenario"), rule.scenario):
            score += 100
            evidence_count += 1
    # CVE number
        if rule.cve and _eq(result.get("cve"), rule.cve):
            score += 80
            evidence_count += 1
    # Product 
        if rule.product and (
            _eq(result.get("product"), rule.product) or
            _contains(result.get("product"), rule.product)
        ):
            score += 30
            evidence_count += 1
    # Version 
        if rule.version and _eq(result.get("version"), rule.version):
            score += 30
            evidence_count += 1
    # Service 
        if rule.service and _eq(result.get("service"), rule.service):
            score += 20
            evidence_count += 1
    # Port 
        if rule.port and result.get("port") == rule.port:
            score += 10
            evidence_count += 1

       # if there isnt evidence of a match then it gets skipped to avoid false positives.
        if evidence_count == 0:
            continue

        
        score += rule.rank

        if score > best_score:
            best = rule
            best_score = score

    return best