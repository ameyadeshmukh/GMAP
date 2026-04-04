import json
import re
from pprint import pprint
from urllib.parse import urlparse

import httpx

from parse_httpx import parse_httpx

TARGETS = [
    "http://127.0.0.1:8081",
    "http://www.google.com"
]

TIMEOUT = 10


def _extract_title(html: str) -> str | None:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else None


def _detect_tech(headers: httpx.Headers) -> list[str]:
    tech = []
    server = headers.get("server", "")
    if server:
        tech.append(server)
    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        tech.append(powered_by)
    if "wp-content" in headers.get("link", ""):
        tech.append("WordPress")
    return tech


def probe(url: str) -> dict:
    parsed = urlparse(url)
    try:
        with httpx.Client(follow_redirects=True, timeout=TIMEOUT) as client:
            resp = client.get(url)

        content_type = resp.headers.get("content-type", "")
        body = resp.text if "html" in content_type else ""

        return {
            "url": str(resp.url),
            "status_code": resp.status_code,
            "title": _extract_title(body),
            "webserver": resp.headers.get("server"),
            "content-type": content_type,
            "content-length": int(resp.headers.get("content-length", len(resp.content))),
            "scheme": parsed.scheme,
            "host": parsed.hostname,
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "tech": _detect_tech(resp.headers),
            "failed": False,
        }
    except Exception as exc:
        return {
            "url": url,
            "failed": True,
            "error": str(exc),
        }


def main():
    print(f"Probing {len(TARGETS)} target(s)...\n")

    lines = []
    for url in TARGETS:
        entry = probe(url)
        status = entry.get("status-code", "FAILED")
        print(f"  {url} → {status}")
        lines.append(json.dumps(entry))

    result = parse_httpx("\n".join(lines))

    print()
    print(f"Accessible URLs : {result['urls_accessible']}")
    print(f"Tech stack      : {result['tech_stack']}")
    print()
    pprint(result)


if __name__ == "__main__":
    main()
