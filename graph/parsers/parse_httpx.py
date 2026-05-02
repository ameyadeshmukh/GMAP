from __future__ import annotations

import json
import time
from typing import Any, Dict


def parse_httpx(raw_output: str) -> Dict[str, Any]:
    """
    Parses httpx JSONL output (one JSON object per line, produced by httpx -json)
    into structured fingerprinting data for the agent state.

    Command that produces this output (from actions.py):
        httpx -u {urls} -json -tech-detect -status-code -title -web-server

    Returns a dict with:
        scan          - metadata about the run
        endpoints     - per-URL probe results
        urls_accessible - URLs that returned a non-error response (maps to state.urls_accessible)
        tech_stack    - deduplicated technology list (maps to state.tech_stack)
    """
    result: Dict[str, Any] = {
        "scan": {
            "tool": "httpx",
            "timestamp": int(time.time()),
        },
        "endpoints": [],
        "urls_accessible": [],
        "tech_stack": [],
    }

    if not raw_output.strip():
        return result

    seen_tech: set = set()

    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Skip probes that failed at the network level
        if entry.get("failed", False):
            continue

        url = entry.get("url", "")
        status_code = entry.get("status_code")

        endpoint: Dict[str, Any] = {
            "url": url,
            "status_code": status_code,
            "title": entry.get("title"),
            "webserver": entry.get("webserver"),
            "content_type": entry.get("content_type"),       
            "content_length": entry.get("content_length"),
            "scheme": entry.get("scheme"),
            "host": entry.get("host"),
            "port": entry.get("port"),
            # tech entries look like ["Apache:2.4.41", "PHP:7.4", "jQuery"]
            "technologies": entry.get("tech", []),
        }

        result["endpoints"].append(endpoint)

        # Accessible = any response below 400 (includes redirects)
        if isinstance(status_code, int) and status_code < 500:
            result["urls_accessible"].append(url)

        # Collect unique technologies across all endpoints
        for tech in entry.get("tech", []):
            if tech not in seen_tech:
                seen_tech.add(tech)
                result["tech_stack"].append(tech)

    return result
