from graph.state import PenTestState
from graph.parsers.tool_nmap import NmapTool, ScanPolicy
from graph.parsers.parse_nmap import normalize_nmap_xml_to_json
from graph.nodes.report_utils import update_or_append_section, generate_report_header

"""
    first phase of pentesting, runs nmap to discover open ports and services

    builds the nmap command for the target using state information
    
    sends the raw output to parse_nmap

    update state
"""

def discovery(state: PenTestState) -> PenTestState:

    nmap = NmapTool()

    target = state["target_host"]
    log = state.get("action_log", [])

    retry_command = state.get("retry_command")

    if retry_command:
        log.append(f"[DISCOVERY] retrying with command: {retry_command}")
        run = nmap.run_raw(retry_command)
    else:
        run = nmap.run(
            intent="TCP_ALL_PORTS",
            targets=[target],
            policy=ScanPolicy(allow_all_ports=True),
            timeout_s=300,
        )

    if run.exit_code != 0:
        log.append(f"nmap failed: {run.stderr}")
        return {**state, "action_log": log}

    parsed = normalize_nmap_xml_to_json(run.stdout_xml, run.targets)
    new_ports = []
    for host in parsed["hosts"]:
        for port in host["ports"]:
            new_ports.append({
                "port":     port["port"],
                "protocol": port["protocol"],
                "service":  port["service"]["name"] if port["service"] else None,
                "version":  f"{port['service'].get('product','')} {port['service'].get('version','')}".strip() if port["service"] else None,
                "ip":       host["ip"],
            })

    existing_ports = state.get("open_ports", [])
    existing_port_numbers = {p["port"] for p in existing_ports}
    merged_ports = existing_ports + [
        p for p in new_ports if p["port"] not in existing_port_numbers
    ]

    log.append(f"[DISCOVERY] nmap found {len(new_ports)} open ports on {target}")
    log.append(f"[DISCOVERY] nmap command: {' '.join(run.args)}")

    # Generate report section for discovery phase
    report_sections = []

    # Add header if this is the first phase (no existing report)
    if not state.get("report"):
        report_sections.append(generate_report_header(state))

    section_header = "## Discovery Phase Results"
    report_sections.append(section_header)

    if merged_ports:
        report_sections.append(f"\n**Total Open Ports:** {len(merged_ports)}\n")
        report_sections.append("| Port | Protocol | Service | Version | IP |")
        report_sections.append("|------|----------|---------|---------|-----|")

        sorted_ports = sorted(merged_ports, key=lambda p: p.get("port", 0))
        for port in sorted_ports:
            report_sections.append(
                f"| {port.get('port', 'N/A')} | "
                f"{port.get('protocol', 'N/A')} | "
                f"{port.get('service', 'N/A')} | "
                f"{port.get('version', 'N/A')} | "
                f"{port.get('ip', 'N/A')} |"
            )
        report_sections.append("")
    else:
        report_sections.append("\nNo open ports discovered.\n")

    new_report = update_or_append_section(state, section_header, "\n".join(report_sections))

    return {
        **state,
        "open_ports": merged_ports,
        "retry_command": None,
        "action_log": log,
        "report": new_report,
    }