from datetime import datetime
from state import PenTestState


def documentation(state: PenTestState) -> PenTestState:
    """
    final phase after the pentest, generates the report with the results

    should include results from each scan and what the agent found as well
    as the exploits ran and what succeeded / failed
    """
    
    log = state.get("action_log", [])
    log.append("[DOCUMENTATION] Generating penetration testing report")
    
    # Build the markdown report
    report_sections = []
    
    # Header
    report_sections.append("# Penetration Testing Report")
    report_sections.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Executive Summary
    report_sections.append("## Executive Summary")
    vuln_count = len(state.get("vulnerabilities", []))
    exploit_results = state.get("exploitation_result", [])
    successful_exploits = sum(1 for e in exploit_results if e.get("success"))
    
    report_sections.append(f"- **Target:** {state.get('target_host', 'N/A')}")
    report_sections.append(f"- **Open Ports:** {len(state.get('open_ports', []))}")
    report_sections.append(f"- **Accessible URLs:** {len(state.get('urls_accessible', []))}")
    report_sections.append(f"- **Vulnerabilities Found:** {vuln_count}")
    report_sections.append(f"- **Successful Exploits:** {successful_exploits}/{len(exploit_results)}\n")
    
    # Target Information
    report_sections.append("## Target Information")
    report_sections.append(f"**Host:** {state.get('target_host', 'N/A')}")
    
    scope = state.get("scope", [])
    report_sections.append(f"**Scope:** {', '.join(scope) if scope else 'None specified'}")
    
    exclusions = state.get("exclusions", [])
    report_sections.append(f"**Exclusions:** {', '.join(exclusions) if exclusions else 'None specified'}")
    
    engagement_rules = state.get("engagement_rules", "")
    report_sections.append(f"**Engagement Rules:** {engagement_rules if engagement_rules else 'None specified'}\n")
    
    # Discovery Results
    report_sections.append("## Discovery Phase Results")
    open_ports = state.get("open_ports", [])
    
    if open_ports:
        report_sections.append(f"\n**Total Open Ports:** {len(open_ports)}\n")
        report_sections.append("| Port | Protocol | Service | Version | IP |")
        report_sections.append("|------|----------|---------|---------|-----|")
        
        sorted_ports = sorted(open_ports, key=lambda p: p.get("port", 0))
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
    
    # Fingerprinting Results
    report_sections.append("## Fingerprinting Phase Results")
    urls = state.get("urls_accessible", [])
    tech_stack = state.get("tech_stack", [])
    http_fingerprint = state.get("http_fingerprint", {})
    
    if urls:
        report_sections.append(f"\n**Accessible URLs:** {len(urls)}\n")
        for url in urls:
            report_sections.append(f"- {url}")
            
            # Add fingerprint details if available
            if url in http_fingerprint:
                fp = http_fingerprint[url]
                if fp.get("status_code"):
                    report_sections.append(f"  - Status: {fp['status_code']}")
                if fp.get("title"):
                    report_sections.append(f"  - Title: {fp['title']}")
                if fp.get("server"):
                    report_sections.append(f"  - Server: {fp['server']}")
        report_sections.append("")
    else:
        report_sections.append("\nNo accessible URLs found.\n")
    
    if tech_stack:
        report_sections.append("**Technologies Identified:**\n")
        for tech in tech_stack:
            report_sections.append(f"- {tech}")
        report_sections.append("")
    else:
        report_sections.append("**Technologies:** No technologies identified.\n")
    
    # Vulnerability Findings
    report_sections.append("## Vulnerability Detection Results")
    vulnerabilities = state.get("vulnerabilities", [])
    
    if vulnerabilities:
        # Group by severity
        severity_groups = {"critical": [], "high": [], "medium": [], "low": [], "info": [], "unknown": []}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown").lower()
            if severity in severity_groups:
                severity_groups[severity].append(vuln)
            else:
                severity_groups["unknown"].append(vuln)
        
        # Summary
        report_sections.append(f"\n**Total Vulnerabilities:** {len(vulnerabilities)}\n")
        report_sections.append("**Severity Breakdown:**")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = len(severity_groups[severity])
            if count > 0:
                report_sections.append(f"- {severity.upper()}: {count}")
        report_sections.append("")
        
        # Detailed findings by severity
        for severity in ["critical", "high", "medium", "low", "info", "unknown"]:
            vulns = severity_groups[severity]
            if not vulns:
                continue
                
            report_sections.append(f"### {severity.upper()} Severity Vulnerabilities\n")
            
            for vuln in vulns:
                report_sections.append(f"**{vuln.get('name', 'Unknown Vulnerability')}**")
                report_sections.append(f"- **Template ID:** {vuln.get('template_id', 'N/A')}")
                if vuln.get('cve_id'):
                    report_sections.append(f"- **CVE:** {vuln['cve_id']}")
                report_sections.append(f"- **URL:** {vuln.get('url', 'N/A')}")
                if vuln.get('description'):
                    report_sections.append(f"- **Description:** {vuln['description']}")
                if vuln.get('cvss_score'):
                    report_sections.append(f"- **CVSS Score:** {vuln['cvss_score']}")
                if vuln.get('cwe_id'):
                    report_sections.append(f"- **CWE:** {vuln['cwe_id']}")
                report_sections.append("")
        
        # MSF modules
        msf_modules = state.get("msf_modules", [])
        if msf_modules:
            report_sections.append("**Mapped Metasploit Modules:**\n")
            for module in msf_modules:
                report_sections.append(f"- {module}")
            report_sections.append("")
    else:
        report_sections.append("\nNo vulnerabilities detected.\n")
    
    # Exploitation Results
    report_sections.append("## Exploitation Phase Results")
    attempted = state.get("attempted_modules", [])
    results = state.get("exploitation_result", [])
    
    if results:
        successful = [r for r in results if r.get("success")]
        failed = [r for r in results if not r.get("success")]
        
        report_sections.append(f"\n**Total Attempts:** {len(results)}")
        report_sections.append(f"**Successful:** {len(successful)}")
        report_sections.append(f"**Failed:** {len(failed)}\n")
        
        if successful:
            report_sections.append("### Successful Exploits\n")
            for result in successful:
                report_sections.append(f"**Module:** {result.get('module', 'N/A')}")
                if result.get('session_type'):
                    report_sections.append(f"- **Session Type:** {result['session_type']}")
                if result.get('output'):
                    report_sections.append(f"- **Output:** ```\n{result['output']}\n```")
                report_sections.append("")
        
        if failed:
            report_sections.append("### Failed Exploitation Attempts\n")
            for result in failed:
                report_sections.append(f"- **Module:** {result.get('module', 'N/A')}")
                if result.get('output'):
                    report_sections.append(f"  - Error: {result['output']}")
            report_sections.append("")
    elif attempted:
        report_sections.append(f"\n**Attempted Modules:** {len(attempted)}")
        for module in attempted:
            report_sections.append(f"- {module}")
        report_sections.append("")
    else:
        report_sections.append("\nNo exploitation attempts made.\n")
    
    # Correlations and Orchestrator Info
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
    report_sections.append("*End of Report*")
    
    # Join all sections
    report = "\n".join(report_sections)
    
    log.append(f"[DOCUMENTATION] Report generated ({len(report)} characters)")
    
    return {
        **state,
        "report": report,
        "action_log": log,
    }