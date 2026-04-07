from state import PenTestState
from parsers.tool_nuclei import NucleiTool, NucleiPolicy
from parsers.parse_nuclei import parse_nuclei


def vuln_detection(state: PenTestState) -> PenTestState:
    """
    third phase, uses nuclei to scan for known vulnerabilities based on 
    information from the state

    calls the nuclei parser and updates the state
    """
    
    nuclei = NucleiTool()
    
    log = state.get("action_log", [])
    
    # Get URLs from fingerprinting phase
    targets = state.get("urls_accessible", [])
    if not targets:
        log.append("[VULN_DETECTION] no accessible URLs found, skipping")
        return {**state, "action_log": log}
    
    # Check for retry command from orchestrator
    retry_command = state.get("retry_command")
    
    if retry_command:
        log.append(f"[VULN_DETECTION] retrying with command: {retry_command}")
        run = nuclei.run_raw(retry_command)
    else:
        # Build policy based on tech stack if available
        tech_stack = state.get("tech_stack", [])
        tags = [tech.lower() for tech in tech_stack] if tech_stack else []
        
        policy = NucleiPolicy(tags=tags) if tags else NucleiPolicy()
        
        run = nuclei.run(
            targets=targets,
            policy=policy,
            timeout_s=600,
        )
    
    if run.exit_code != 0:
        log.append(f"[VULN_DETECTION] nuclei failed: {run.stderr}")
        return {**state, "action_log": log}
    
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
    
    return {
        **state,
        "vulnerabilities": merged_vulns,
        "retry_command": None,
        "action_log": log,
    }