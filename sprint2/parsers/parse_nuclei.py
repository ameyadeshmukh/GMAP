from __future__ import annotations

import json
import time
from typing import Any, Dict, List


def parse_nuclei(raw_output: str) -> Dict[str, Any]:
    """
    Parses nuclei JSONL output (one JSON object per line, produced by nuclei -json)
    into structured vulnerability data for the agent state.

    Command that produces this output (from actions.py):
        nuclei -u {urls_accessible} -json -severity critical,high,medium

    Returns a dict with:
        scan            - metadata about the run
        vulnerabilities - per-finding results with template_id, cve_id, severity,
                          url, description, and classification info
                          (maps to state.vulnerabilities)
    """
    result: Dict[str, Any] = {
        "scan": {
            "tool": "nuclei",
            "timestamp": int(time.time()),
        },
        "vulnerabilities": [],
    }

    if not raw_output.strip():
        return result

    seen: set = set()

    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = entry.get("info", {})
        classification = info.get("classification", {})

        template_id = entry.get("template-id", "")
        matched_at = entry.get("matched-at", entry.get("host", ""))

        # nuclei can return cve-id as a list or a single string
        raw_cve = classification.get("cve-id")
        if isinstance(raw_cve, list):
            cve_id = raw_cve[0] if raw_cve else None
        else:
            cve_id = raw_cve

        severity = info.get("severity", "unknown")

        # deduplicate on (template_id, matched_at) to avoid repeat findings
        dedup_key = (template_id, matched_at)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        vuln: Dict[str, Any] = {
            "template_id": template_id,
            "cve_id": cve_id,
            "severity": severity,
            "url": matched_at,
            "name": info.get("name"),
            "description": info.get("description"),
            "tags": info.get("tags", []),
            "references": info.get("reference", []),
            "cvss_score": classification.get("cvss-score"),
            "cwe_id": classification.get("cwe-id"),
            "matcher_name": entry.get("matcher-name"),
            "type": entry.get("type"),
            "host": entry.get("host"),
            "ip": entry.get("ip"),
            "timestamp": entry.get("timestamp"),
        }

        result["vulnerabilities"].append(vuln)

    # Sort by severity so critical/high findings surface first
    _severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    result["vulnerabilities"].sort(
        key=lambda v: _severity_rank.get(v.get("severity", "unknown"), 5)
    )

    return result
