from datetime import datetime
from graph.state import PenTestState
from graph.nodes.report_utils import append_to_report


def documentation(state: PenTestState) -> PenTestState:
    """
    Final phase after the pentest. Adds executive summary, agent analysis,
    action log, and severity scale reference to complete the report.

    The bulk of the report is already generated incrementally by each phase node.
    """

    log = state.get("action_log", [])
    log.append("[DOCUMENTATION] Finalizing penetration testing report")

    # Build final report sections to append
    report_sections = []

    # Executive Summary (add at top via prepend logic below)
    exec_summary = []
    exec_summary.append("## Executive Summary")
    vuln_count = len(state.get("vulnerabilities", []))
    exploit_results = state.get("exploitation_result", [])
    successful_exploits = 0
    if exploit_results:
        successful_exploits = sum(1 for e in exploit_results if e.get("success"))

    exec_summary.append(f"- **Target:** {state.get('target_host', 'N/A')}")
    exec_summary.append(f"- **Open Ports:** {len(state.get('open_ports', []))}")
    exec_summary.append(f"- **Accessible URLs:** {len(state.get('urls_accessible', []))}")
    exec_summary.append(f"- **Vulnerabilities Found:** {vuln_count}")
    if exploit_results:
        exec_summary.append(f"- **Successful Exploits:** {successful_exploits}/{len(exploit_results)}\n")
    else:
        exec_summary.append("")

    # Agent Analysis and Orchestrator Info
    report_sections.append("## Agent Analysis")
    correlations = state.get("correlations", [])

    if correlations:
        report_sections.append("\n**Correlations Identified:**\n")
        for corr in correlations:
            report_sections.append(f"- {corr}")
        report_sections.append("")
    else:
        report_sections.append("\nNo correlations identified.\n")

    iterations = state.get("iterations", 0)
    current_phase = state.get("current_phase", "N/A")
    report_sections.append(f"**Total Iterations:** {iterations}")
    report_sections.append(f"**Final Phase:** {current_phase}\n")

    # Action Log
    report_sections.append("## Action Log")
    action_log = state.get("action_log", [])

    if action_log:
        report_sections.append("\n```")
        for entry in action_log:
            report_sections.append(entry)
        report_sections.append("```\n")
    else:
        report_sections.append("\nNo actions logged.\n")

    # Footer
    report_sections.append("---")
    report_sections.append("\n## Severity Scale Reference\n")
    report_sections.append("This report uses a normalized severity scoring system (1-12 scale) across all tools:\n")
    report_sections.append("| Score Range | Severity Level | Description |")
    report_sections.append("|-------------|----------------|-------------|")
    report_sections.append("| 0 | INFO | Informational findings, no immediate risk |")
    report_sections.append("| 1-3 | LOW | Minor issues, low exploitability |")
    report_sections.append("| 4-6 | MEDIUM | Moderate risk, requires attention |")
    report_sections.append("| 7-9 | HIGH | Serious vulnerabilities, high priority |")
    report_sections.append("| 10-12 | CRITICAL | Severe issues, immediate action required |")
    report_sections.append("\n*End of Report*")

    # Append final sections to existing report
    final_report = append_to_report(state, "\n".join(report_sections))

    # Insert executive summary after target information
    # Split the report to insert exec summary after "## Target Information" section
    if "## Target Information" in final_report:
        parts = final_report.split("## Discovery Phase Results", 1)
        if len(parts) == 2:
            final_report = parts[0] + "\n".join(exec_summary) + "\n\n## Discovery Phase Results" + parts[1]

    log.append(f"[DOCUMENTATION] Report finalized ({len(final_report)} characters)")

    return {
        **state,
        "report": final_report,
        "action_log": log,
    }