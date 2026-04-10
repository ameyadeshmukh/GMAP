from datetime import datetime, UTC
from state import PenTestState


def documentation(state: PenTestState) -> PenTestState:
    """
    final phase after the pentest, generates the report with the results

    should include results from each scan and what the agent found as well
    as the exploits ran and what succeeded / failed
    """
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    target = state.get("target_host", "unknown")

    open_ports        = state.get("open_ports", [])
    urls_accessible   = state.get("urls_accessible", [])
    tech_stack        = state.get("tech_stack", [])
    vulnerabilities   = state.get("vulnerabilities", [])
    msf_modules       = state.get("msf_modules", [])
    attempted_modules = state.get("attempted_modules", [])
    exploitation_result = state.get("exploitation_result") or []
    correlations      = state.get("correlations", [])
    action_log        = state.get("action_log", [])
    human_decision    = state.get("human_decision", "N/A")
    iterations        = state.get("iterations", 0)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    sorted_vulns = sorted(vulnerabilities, key=lambda v: severity_order.get(v.get("severity", "unknown"), 5))

    lines = []

    lines.append("=" * 70)
    lines.append("GMAP PENETRATION TEST REPORT")
    lines.append("=" * 70)
    lines.append(f"Generated : {now}")
    lines.append(f"Target    : {target}")
    lines.append(f"Scope     : {', '.join(state.get('scope', [target]))}")
    rules = state.get("engagement_rules", "")
    if rules:
        lines.append(f"Rules     : {rules}")
    lines.append(f"Iterations: {iterations}")
    lines.append(f"Human decision: {human_decision}")
    lines.append("")

    # executive summary
    lines.append("-" * 70)
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 70)
    lines.append(f"  Open ports discovered : {len(open_ports)}")
    lines.append(f"  HTTP endpoints probed : {len(urls_accessible)}")
    lines.append(f"  Technologies detected : {len(tech_stack)}")
    lines.append(f"  Vulnerabilities found : {len(vulnerabilities)}")
    critical = sum(1 for v in vulnerabilities if v.get("severity") == "critical")
    high     = sum(1 for v in vulnerabilities if v.get("severity") == "high")
    if vulnerabilities:
        lines.append(f"    Critical: {critical}  High: {high}  Other: {len(vulnerabilities) - critical - high}")
    lines.append(f"  MSF modules matched   : {len(msf_modules)}")
    lines.append(f"  Exploitation attempts : {len(attempted_modules)}")
    lines.append("")

    # discovery
    lines.append("-" * 70)
    lines.append("DISCOVERY  (nmap)")
    lines.append("-" * 70)
    if open_ports:
        lines.append(f"  {'PORT':<8} {'PROTO':<8} {'SERVICE':<18} {'VERSION'}")
        for p in sorted(open_ports, key=lambda x: x.get("port", 0)):
            lines.append(
                f"  {str(p.get('port','')):<8} "
                f"{p.get('protocol',''):<8} "
                f"{(p.get('service') or 'unknown'):<18} "
                f"{p.get('version') or ''}"
            )
    else:
        lines.append("  No open ports found.")
    lines.append("")

    # fingerprinting
    lines.append("-" * 70)
    lines.append("FINGERPRINTING  (httpx)")
    lines.append("-" * 70)
    if urls_accessible:
        lines.append("  Accessible URLs:")
        for u in urls_accessible:
            lines.append(f"    {u}")
    else:
        lines.append("  No accessible HTTP endpoints.")
    if tech_stack:
        lines.append(f"  Tech stack: {', '.join(tech_stack)}")
    lines.append("")

    # vulnerabilities
    lines.append("-" * 70)
    lines.append("VULNERABILITIES  (nuclei)")
    lines.append("-" * 70)
    if sorted_vulns:
        for i, v in enumerate(sorted_vulns, 1):
            lines.append(f"  {i}. [{v.get('severity','unknown').upper()}] {v.get('cve_id') or v.get('template_id','N/A')}")
            lines.append(f"     URL         : {v.get('url','N/A')}")
            lines.append(f"     Description : {v.get('description','')}")
            lines.append("")
    else:
        lines.append("  No vulnerabilities detected.")
        lines.append("")

    # msf modules
    lines.append("-" * 70)
    lines.append("METASPLOIT MODULE MATCHES")
    lines.append("-" * 70)
    if msf_modules:
        for m in msf_modules:
            lines.append(f"  {m}")
    else:
        lines.append("  No modules matched.")
    lines.append("")

    # exploitation
    lines.append("-" * 70)
    lines.append("EXPLOITATION RESULTS")
    lines.append("-" * 70)
    if attempted_modules:
        lines.append(f"  Modules attempted: {', '.join(attempted_modules)}")
    if exploitation_result:
        for r in exploitation_result:
            status = "SUCCESS" if r.get("success") else "FAILED"
            lines.append(f"  [{status}] {r.get('module','')}")
            if r.get("session_type"):
                lines.append(f"    Session type : {r['session_type']}")
            if r.get("output"):
                lines.append(f"    Output       : {r['output']}")
    if not attempted_modules and not exploitation_result:
        lines.append("  No exploitation attempted.")
    lines.append("")

    # correlations
    if correlations:
        lines.append("-" * 70)
        lines.append("ORCHESTRATOR CORRELATIONS")
        lines.append("-" * 70)
        for c in correlations:
            lines.append(f"  - {c}")
        lines.append("")

    # action log
    lines.append("-" * 70)
    lines.append("AGENT ACTION LOG")
    lines.append("-" * 70)
    for entry in action_log:
        lines.append(f"  {entry}")
    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)

    report = "\n".join(lines)

    return {**state, "report": report}
