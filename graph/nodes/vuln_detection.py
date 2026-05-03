from graph.state import PenTestState
from graph.parsers.tool_nuclei import NucleiTool, NucleiPolicy
from graph.parsers.parse_nuclei import parse_nuclei
from graph.parsers.severity_normalizer import normalize_finding, get_severity_distribution
from graph.nodes.report_utils import update_or_append_section


TECH_TAG_MAP = {
    "java": ["struts", "spring", "java", "log4j"],
    "jetty": ["struts", "spring", "java", "jetty"],
    "tomcat": ["struts", "spring", "java", "tomcat"],
    "apache": ["apache", "struts"],
    "php": ["php", "wordpress", "drupal", "laravel"],
    "python": ["python", "django", "flask"],
    "nginx": ["nginx"],
    "iis": ["iis", "asp"],
    "grafana": ["grafana"],
    "jenkins": ["jenkins"],
    "confluence": ["confluence"],
    "jboss": ["jboss", "java"],
    "wordpress": ["wordpress", "wp"],
}

def _resolve_tags(tech_stack: list) -> list:
    tags = set()
    for tech in tech_stack:
        tech_lower = tech.lower().split(":")[0]  # strip version 
        for key, mapped_tags in TECH_TAG_MAP.items():
            if key in tech_lower:
                tags.update(mapped_tags)
    return list(tags)

def vuln_detection(state: PenTestState) -> PenTestState:
    """
    third phase, uses nuclei to scan for known vulnerabilities based on 
    information from the state

    calls the nuclei parser and updates the state
    """
    
    nuclei = NucleiTool()
    
    log = state.get("action_log", [])
    
    # Get URLs from fingerprinting phase

    urls_accessible = state.get("urls_accessible", [])
    open_ports = state.get("open_ports", [])

    if not urls_accessible and open_ports:
        # build targets directly from open ports and let nuclei figure out paths
        for p in open_ports:
            scheme = "https" if "https" in (p.get("service") or "") else "http"
            urls_accessible.append(f"{scheme}://{state['target_host']}:{p['port']}")
        log.append(f"[VULN_DETECTION] no accessible URLs from httpx, falling back to port-based targets: {urls_accessible}")

    targets = urls_accessible

    if not urls_accessible:
        log.append("[VULN_DETECTION] no targets available, skipping")
        return {**state, "action_log": log}
    
    # Check for retry command from orchestrator
    retry_command = state.get("retry_command")
    
    if retry_command:
        log.append(f"[VULN_DETECTION] retrying with command: {retry_command}")
        run = nuclei.run_raw(retry_command)
    else:
        # Build policy based on tech stack if available
        tech_stack = state.get("tech_stack", [])
        resolved_tags = _resolve_tags(tech_stack)

        policy = NucleiPolicy(tags=resolved_tags) if resolved_tags else NucleiPolicy()
        #tags = [tech.lower() for tech in tech_stack] if tech_stack else []
        
        #policy = NucleiPolicy(tags=tags) if tags else NucleiPolicy()
        log.append(f"[VULN_DETECTION] targets: {targets}")
        
        run = nuclei.run(
            targets=targets,
            policy=policy,
            timeout_s=600,
        )
        log.append(f"[VULN_DETECTION] stderr: {run.stderr[:500]}")
        log.append(f"[VULN_DETECTION] stdout raw: {repr(run.stdout_jsonl[:500])}")

        # if run.exit_code != 0:
    #     log.append(f"[VULN_DETECTION] nuclei failed: {run.stderr}")
    #     return {**state, "action_log": log}
    
    # Parse nuclei JSONL output
    parsed = parse_nuclei(run.stdout_jsonl)
    
    # Merge with existing vulnerabilities
    existing_vulns = state.get("vulnerabilities", [])
    new_vulns = parsed["vulnerabilities"]
    
    # Deduplicate based on (template_id, url)
    seen = {(v.get("template_id"), v.get("url")) for v in existing_vulns}
    merged_vulns = existing_vulns + [
        v for v in new_vulns 
        if (v.get("template_id"), v.get("url")) not in seen
    ]
    
    log.append(f"[VULN_DETECTION] nuclei found {len(new_vulns)} vulnerabilities")
    log.append(f"[VULN_DETECTION] nuclei command: {' '.join(run.args)}")

    # Generate report section for vulnerability detection phase
    report_sections = []
    section_header = "## Vulnerability Detection Results"
    report_sections.append(section_header)

    if merged_vulns:
        # Add normalized severity scores to each vulnerability
        scored_vulns = []
        for vuln in merged_vulns:
            severity_score = normalize_finding(vuln, "nuclei")
            vuln_with_score = {**vuln, "normalized_score": severity_score.score, "normalized_level": severity_score.level.value}
            scored_vulns.append(vuln_with_score)

        # Sort by normalized score (highest first)
        scored_vulns.sort(key=lambda v: v["normalized_score"], reverse=True)

        # Group by severity
        severity_groups = {"critical": [], "high": [], "medium": [], "low": [], "info": [], "unknown": []}
        for vuln in scored_vulns:
            severity = vuln.get("severity", "unknown").lower()
            if severity in severity_groups:
                severity_groups[severity].append(vuln)
            else:
                severity_groups["unknown"].append(vuln)

        # Summary with normalized scores
        report_sections.append(f"\n**Total Vulnerabilities:** {len(merged_vulns)}\n")
        report_sections.append("**Severity Breakdown:**")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = len(severity_groups[severity])
            if count > 0:
                report_sections.append(f"- {severity.upper()}: {count}")

        # Show severity distribution from normalizer
        severity_dist = get_severity_distribution(merged_vulns, "nuclei")
        report_sections.append("\n**Normalized Severity Distribution:**")
        for level in ["critical", "high", "medium", "low", "info"]:
            if severity_dist[level] > 0:
                report_sections.append(f"- {level.upper()}: {severity_dist[level]}")
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
                report_sections.append(f"- **Normalized Score:** {vuln.get('normalized_score', 'N/A')}/12 ({vuln.get('normalized_level', 'N/A').upper()})")
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

    new_report = update_or_append_section(state, section_header, "\n".join(report_sections))

    return {
        **state,
        "vulnerabilities": merged_vulns,
        "retry_command": None,
        "action_log": log,
        "report": new_report,
    }










