"""
Most of this is instructions for the LLM. The preconditions should be checked in each of the nodes
before running anything. If the command might need modifications some of those are listed in the 
guidance section. The expected output here can be changed based on how we make the parsers but should 
be somewhat similar to what is in here now.  
"""
ACTIONS = [
    {
        "id": "discovery",
        "description": "Use nmap to scan all ports on the target to identify open ports and running services",
        "preconditions": {
            "target_known": True,
            "scope_defined": True
        },
        "command_template": "nmap -sV -p- --open -T4 {target_host}",
        "expected_output": (
            "List of open ports including port number, protocol, and service name. "
            "Version information is not required — httpx will handle service fingerprinting. "
            "Success is defined as finding at least one open port."
        ),
        "guidance": (
            "advance if open ports are found, even without version info. "
            "Only retry if the scan timed out or no ports were found on a live host. "
            "If the scan is timing out, switch to --top-ports 1000. "
            "If host appears down, ABORT and report to user. "
            "Do not retry just because service versions are missing."
        )
    },
    {
        "id": "fingerprinting",
        "description": "Use httpx to probe  HTTP/HTTPS ports found in discovery to extract tech stack and live URLs",
        "preconditions": {
            "ports_found": True,
            "http_services_found": True
        },
        "command_template": "httpx -u {http_urls_from_open_ports} -json -tech-detect -status-code -title -web-server",
        "expected_output": (
            "For each probed URL, output should include status code, page title, web server header, "
            "detected technologies with versions. Used to populate urls_accessible, "
            "tech_stack, and http_fingerprint in state."
        ),
        "guidance": (
            "This stage should build a URL list directly from HTTP/HTTPS ports found in discovery,"
            "formmated like this: http://target:80, https://target:443 "
            "With these urls, include tech stack, version numbers, status codes, and accessible URLs. "
            "If probing multiple ports, pass a list with -l instead of -u. "
            "If probing a specific single port, use -u target:port directly."
        )
    },
    {
        "id": "vuln_detection",
        "description": "Scan the live URLs found with nuclei to confirm potential vulnerabilities",
        "preconditions": {
            "ports_found": True,
            "urls_found": True
        },
        "command_template": "nuclei -u {urls_accessible} -json -severity critical,high,medium",
        "expected_output": (
            "Output should include a list of confirmed vulnerabilities each with a template ID, CVE ID, "
            "severity, affected URL, description. Used to populate vulnerabilities in state."
            "orchestrator can then map these cves to msf modules from the module map"
        ),
        "guidance": (
            "Use the urls_accessible from fingerprinting as targets for this step. "
            "to target specific tech found in fingerprinting, add -tags {tech} "
            "e.g. -tags apache, -tags wordpress, -tags confluence, -tags tomcat. "
            "If first pass returns no results, try -severity medium,low instead. "
            "after mapping confirmed CVEs to metasploit modules populate msf_modules in state. "
            "should be ranked based on severity and whether msf module was found"
        )
    },
    {
        # the graph should be directed to this stage when either something fails or before exploitation
        "id": "review",
        "description": "Pause the loop and present findings to user before exploitation",
        "preconditions": {
            "vulns_found": True,
            "msf_modules_found": True
        },
        "command_template": None,
        "expected_output": (
            "Human decision: approve, skip, or abort. "
            "Used to set human_decision in state."
        ),
        "guidance": (
            "Present the ranked vulnerabilities and matched msf_modules to the user. "
            "Include the CVE, severity, affected service and port, and msf module. "
            "if decision is approve then proceed to exploitation, "
            "if skipped go straight to documentation"
        )
    },
    {
        "id": "exploitation",
        "description": "Attempt exploitation using metasploit against confirmed vulnerabilities",
        "preconditions": {
            "human_approved": True,
            "msf_modules_found": True,
            "modules_remaining": True
        },
        # this command is a one liner for now but i'm not sure how well this will work with the LLM
        # so maybe in the future could do multiple more interactive metasploit commands
        "command_template": "msfconsole -q -x 'use {msf_module}; set RHOSTS {target_host}; set RPORT {port}; check; run; exit'",
        "expected_output": (
            "Include the exploitation result, session type and privileges if successful, "
            "or error message if failed. Used to populate exploitation_result "
            "and attempted_modules in state."
        ),
        "guidance": (
            "Always run check before run if the module supports it. "
            "If a module requires a reverse shell callback, add set LHOST {lhost}. "
            "If check confirms vulnerable, proceed with run. "
            "Record each attempt in attempted_modules. "
            "If module fails move to the next ranked module. "
            "Stop and move to documentation once all modules exhausted."
        )
    },
    {
        "id": "documentation",
        "description": "Compile all findings and actions into a final pentest report",
        "preconditions": {
            "target_known": True
        },
        "command_template": None,
        "expected_output": (
            "Structured pentest report covering all phases and information from state. "
            "Used to populate report in state."
        ),
        "guidance": (
            "Compile report from full action_log, discovered ports and services, "
            "tech stack, vulnerabilities ranked by severity, and exploitation results. "
        )
    }
]