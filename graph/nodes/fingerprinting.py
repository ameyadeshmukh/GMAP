from graph.state import PenTestState
from graph.parsers.tool_httpx import HttpxTool, HttpxPolicy
from graph.parsers.parse_httpx import parse_httpx


def fingerprinting_node(state):
    """
    second pentesting phase, runs httpx against HTTP services found during
    the discovery phase

    uses the state to figure out what type of scans to run

    call the parser for httpx and update the state
    """


httpx = HttpxTool(httpx_path="pd-httpx")

def fingerprinting(state: PenTestState) -> PenTestState:
    log = state.get("action_log", [])

    # build URL list from ports found in discovery
    http_services = ["http", "https", "http-alt", "ssl/http", "ssl/https, http-proxy"]
    http_ports = [
        p for p in state.get("open_ports", [])
        if p.get("service") in http_services
    ]
    if not http_ports:
        log.append("no HTTP/HTTPS ports found, skipping")
        return {**state, "action_log": log}

    # target URL list
    targets = []
    for p in http_ports:
        scheme = "https" if "https" in (p.get("service") or "") else "http"
        targets.append(f"{scheme}://{state['target_host']}:{p['port']}")

    run = httpx.run(
        targets=targets,
        policy=HttpxPolicy(),
        timeout_s=120,
    )
    if run.exit_code != 0:
        log.append(f"httpx failed: {run.stderr}")
        return {**state, "action_log": log}

    parsed = parse_httpx(run.stdout_jsonl)
    existing_urls = state.get("urls_accessible", [])
    existing_tech = state.get("tech_stack", [])
    existing_fingerprint = state.get("http_fingerprint", {})
    merged_urls = list(set(existing_urls + parsed["urls_accessible"]))
    merged_tech = list(set(existing_tech + parsed["tech_stack"]))
    merged_fingerprint = {**existing_fingerprint}
    for endpoint in parsed["endpoints"]:
        merged_fingerprint[endpoint["url"]] = endpoint

    log.append(f"httpx probed {len(targets)} URLs")
    log.append(f"httpx accessible: {parsed['urls_accessible']}")
    log.append(f"httpx tech stack: {parsed['tech_stack']}")

    return {
        **state,
        "urls_accessible":  merged_urls,
        "tech_stack":       merged_tech,
        "http_fingerprint": merged_fingerprint,
        "action_log":       log,
    }