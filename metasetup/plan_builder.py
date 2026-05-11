# This program is for building the final plan based on the matched rules and the initial discovery results

from urllib.parse import urlparse

def _extract_target_uri(result: dict):
    if result.get("target_uri"):
        return result["target_uri"]

    url = result.get("url")
    if not url:
        return None

    try:
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            return f"{path}?{parsed.query}"
        return path
    except Exception:
        return None

def build_plan(result: dict, rule) -> dict:
    options = dict(rule.default_options)

    options["RHOSTS"] = result["host"]

    if result.get("port"):
        options.setdefault("RPORT", result["port"])

    target_uri = _extract_target_uri(result)
    if target_uri:
        options.setdefault("TARGETURI", target_uri)

    return {
        "rule_id": rule.rule_id,
        "scenario": rule.scenario,
        "module": rule.module,
        "options": options,
        "requires_approval": rule.requires_approval,
        "validation_required": rule.validation_required,
    }