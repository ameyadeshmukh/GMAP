from graph.state import PenTestState
from graph.parsers.tool_httpx import HttpxTool, HttpxPolicy
from graph.parsers.parse_httpx import parse_httpx
from graph.nodes.report_utils import update_or_append_section


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
    COMMON_HTTP_PORTS = {80, 443, 8080, 8443, 8161, 8983, 8888, 8008, 9200, 9000, 3000, 5000}

    http_services = {"http", "https", "http-alt", "ssl/http", "http-proxy"}

    http_ports = [
        p for p in state.get("open_ports", [])
        if p.get("service") in http_services
        or p.get("port") in COMMON_HTTP_PORTS
    ]
    if not http_ports:
        log.append("no HTTP/HTTPS ports found, skipping")
        return {**state, "action_log": log}

    # target URL list
    targets = []
    for p in http_ports:
        scheme = "https" if "https" in (p.get("service") or "") else "http"
        targets.append(f"{scheme}://{state['target_host']}:{p['port']}")

    retry_command = state.get("retry_command")

    if retry_command:
        log.append(f"[FINGERPRINTING] retrying with command: {retry_command}")
        run = httpx.run_raw(retry_command)
    else:
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

    log.append(f"[FINGERPRINTING] httpx probed {len(targets)} URLs")
    log.append(f"[FINGERPRINTING] httpx accessible: {parsed['urls_accessible']}")
    log.append(f"[FINGERPRINTING] httpx tech stack: {parsed['tech_stack']}")

    # Generate report section for fingerprinting phase
    report_sections = []
    section_header = "## Fingerprinting Phase Results"
    report_sections.append(section_header)

    # Add probe details
    report_sections.append("\n**Probe Details:**")
    report_sections.append(f"- **HTTP Ports Identified:** {len(http_ports)}")
    report_sections.append(f"- **URLs Probed:** {len(targets)}")
    report_sections.append(f"- **Probe Type:** {'Retry scan' if retry_command else 'Standard HTTP fingerprinting'}")
    if targets:
        report_sections.append(f"- **Targets:** {', '.join(targets[:5])}{' ...' if len(targets) > 5 else ''}")
    report_sections.append("")

    if merged_urls:
        report_sections.append(f"**Accessible URLs:** {len(merged_urls)}")
        new_urls = len(parsed["urls_accessible"])
        if new_urls < len(merged_urls):
            report_sections.append(f"**New URLs Found:** {new_urls} (previously discovered: {len(merged_urls) - new_urls})")
        report_sections.append("")

        for url in merged_urls:
            report_sections.append(f"- {url}")

            # Add fingerprint details if available
            if url in merged_fingerprint:
                fp = merged_fingerprint[url]
                if fp.get("status_code"):
                    report_sections.append(f"  - Status: {fp['status_code']}")
                if fp.get("title"):
                    report_sections.append(f"  - Title: {fp['title']}")
                if fp.get("server"):
                    report_sections.append(f"  - Server: {fp['server']}")
        report_sections.append("")
    else:
        report_sections.append("**Result:** No accessible URLs found.")

    if merged_tech:
        report_sections.append("**Technologies Identified:**")
        new_tech = len(parsed["tech_stack"])
        if new_tech < len(merged_tech):
            report_sections.append(f"*New: {new_tech} | Total: {len(merged_tech)}*")
        report_sections.append("")
        for tech in merged_tech:
            report_sections.append(f"- {tech}")
        report_sections.append("")
    else:
        if merged_urls:
            report_sections.append("**Technologies:** No specific technologies identified.")
            report_sections.append("*Note: Web applications may be using custom stacks or obfuscation techniques.*\n")
        else:
            report_sections.append("**Technologies:** Cannot identify (no accessible URLs)\n")

    new_report = update_or_append_section(state, section_header, "\n".join(report_sections))

    return {
        **state,
        "urls_accessible":  merged_urls,
        "tech_stack":       merged_tech,
        "retry_command": None,
        "http_fingerprint": merged_fingerprint,
        "action_log":       log,
        "report": new_report,
    }