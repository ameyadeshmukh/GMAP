"""
Demonstration of Severity Normalization Layer

Shows how findings from different tools are normalized to a unified 1-12 scale.
"""

from graph.parsers.severity_normalizer import normalize_finding, get_severity_distribution
from pprint import pprint


def demo_nuclei_normalization():
    print("=" * 80)
    print("NUCLEI VULNERABILITY NORMALIZATION")
    print("=" * 80)
    
    nuclei_findings = [
        {
            "template_id": "CVE-2021-44228",
            "cve_id": "CVE-2021-44228",
            "severity": "critical",
            "cvss_score": "10.0",
            "name": "Log4j RCE",
            "url": "http://target:8080",
        },
        {
            "template_id": "sql-injection",
            "severity": "high",
            "cvss_score": "8.5",
            "name": "SQL Injection",
            "url": "http://target/login",
        },
        {
            "template_id": "xss-reflected",
            "severity": "medium",
            "cvss_score": "6.1",
            "name": "Reflected XSS",
            "url": "http://target/search",
        },
        {
            "template_id": "info-disclosure",
            "severity": "low",
            "name": "Information Disclosure",
            "url": "http://target/debug",
        },
        {
            "template_id": "tech-detect",
            "severity": "info",
            "name": "Apache Detected",
            "url": "http://target",
        },
    ]
    
    for vuln in nuclei_findings:
        score = normalize_finding(vuln, "nuclei")
        print(f"\n{vuln['name']}:")
        print(f"  Original Severity: {vuln['severity']}")
        print(f"  Normalized Score: {score.score}/12")
        print(f"  Severity Level: {score.level.value.upper()}")
        print(f"  Reasoning: {score.reasoning}")
    
    print("\n" + "-" * 80)
    dist = get_severity_distribution(nuclei_findings, "nuclei")
    print("Severity Distribution:")
    pprint(dist)


def demo_nmap_normalization():
    print("\n" + "=" * 80)
    print("NMAP PORT DISCOVERY NORMALIZATION")
    print("=" * 80)
    
    nmap_findings = [
        {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.2"},
        {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache 2.4"},
        {"port": 443, "protocol": "tcp", "service": "https", "version": "nginx 1.18"},
        {"port": 3306, "protocol": "tcp", "service": "mysql", "version": "MySQL 5.7"},
        {"port": 3389, "protocol": "tcp", "service": "rdp", "version": "Microsoft RDP"},
        {"port": 23, "protocol": "tcp", "service": "telnet", "version": None},
        {"port": 445, "protocol": "tcp", "service": "smb", "version": "Samba 4.0"},
    ]
    
    for port in nmap_findings:
        score = normalize_finding(port, "nmap")
        print(f"\nPort {port['port']}/{port['protocol']} ({port['service']}):")
        print(f"  Normalized Score: {score.score}/12")
        print(f"  Severity Level: {score.level.value.upper()}")
        print(f"  Reasoning: {score.reasoning}")
    
    print("\n" + "-" * 80)
    dist = get_severity_distribution(nmap_findings, "nmap")
    print("Severity Distribution:")
    pprint(dist)


def demo_httpx_normalization():
    print("\n" + "=" * 80)
    print("HTTPX FINGERPRINTING NORMALIZATION")
    print("=" * 80)
    
    httpx_findings = [
        {
            "url": "http://target:80",
            "status_code": 200,
            "technologies": ["Apache:2.4", "PHP:7.4"],
            "webserver": "Apache/2.4.41",
        },
        {
            "url": "http://target:80/admin",
            "status_code": 200,
            "technologies": ["WordPress:5.8"],
            "webserver": "nginx",
        },
        {
            "url": "http://target:8080/phpmyadmin",
            "status_code": 200,
            "technologies": ["phpMyAdmin:4.9"],
            "webserver": "Apache",
        },
        {
            "url": "http://target:80/api",
            "status_code": 401,
            "technologies": [],
            "webserver": "nginx",
        },
        {
            "url": "http://target:80/error",
            "status_code": 500,
            "technologies": [],
            "webserver": "Apache",
        },
    ]
    
    for endpoint in httpx_findings:
        score = normalize_finding(endpoint, "httpx")
        print(f"\n{endpoint['url']}:")
        print(f"  Status Code: {endpoint['status_code']}")
        print(f"  Normalized Score: {score.score}/12")
        print(f"  Severity Level: {score.level.value.upper()}")
        print(f"  Reasoning: {score.reasoning}")
    
    print("\n" + "-" * 80)
    dist = get_severity_distribution(httpx_findings, "httpx")
    print("Severity Distribution:")
    pprint(dist)


def demo_exploit_normalization():
    print("\n" + "=" * 80)
    print("EXPLOITATION RESULTS NORMALIZATION")
    print("=" * 80)
    
    exploit_findings = [
        {
            "module": "exploit/multi/http/struts2_content_type_ognl",
            "success": True,
            "session_type": "meterpreter",
            "output": "Session 1 opened",
        },
        {
            "module": "exploit/linux/http/apache_mod_cgi_bash_env_exec",
            "success": True,
            "session_type": "shell",
            "output": "Command shell opened",
        },
        {
            "module": "exploit/windows/smb/ms17_010_eternalblue",
            "success": False,
            "output": "Exploit failed: connection timeout",
        },
        {
            "module": "auxiliary/scanner/http/wordpress_login_enum",
            "success": False,
            "output": "No valid credentials found",
        },
    ]
    
    for exploit in exploit_findings:
        score = normalize_finding(exploit, "metasploit")
        print(f"\n{exploit['module']}:")
        print(f"  Success: {exploit['success']}")
        print(f"  Normalized Score: {score.score}/12")
        print(f"  Severity Level: {score.level.value.upper()}")
        print(f"  Reasoning: {score.reasoning}")
    
    print("\n" + "-" * 80)
    dist = get_severity_distribution(exploit_findings, "metasploit")
    print("Severity Distribution:")
    pprint(dist)


def demo_unified_view():
    print("\n" + "=" * 80)
    print("UNIFIED SEVERITY VIEW ACROSS ALL TOOLS")
    print("=" * 80)
    
    # Collect all findings with normalized scores
    all_findings = []
    
    # Critical vulnerability
    all_findings.append({
        "tool": "nuclei",
        "finding": {"severity": "critical", "cve_id": "CVE-2021-44228", "name": "Log4j RCE"},
    })
    
    # Successful exploit
    all_findings.append({
        "tool": "metasploit",
        "finding": {"success": True, "module": "struts2_rce", "session_type": "meterpreter"},
    })
    
    # High-risk service
    all_findings.append({
        "tool": "nmap",
        "finding": {"port": 3389, "service": "rdp", "protocol": "tcp"},
    })
    
    # Risky web app
    all_findings.append({
        "tool": "httpx",
        "finding": {"url": "http://target/phpmyadmin", "status_code": 200, "technologies": ["phpMyAdmin"]},
    })
    
    # Medium vulnerability
    all_findings.append({
        "tool": "nuclei",
        "finding": {"severity": "medium", "name": "XSS", "url": "http://target/search"},
    })
    
    # Sort by normalized score (highest first)
    scored_findings = []
    for item in all_findings:
        score = normalize_finding(item["finding"], item["tool"])
        scored_findings.append({
            "tool": item["tool"],
            "score": score.score,
            "level": score.level.value,
            "reasoning": score.reasoning,
        })
    
    scored_findings.sort(key=lambda x: x["score"], reverse=True)
    
    print("\nFindings ranked by normalized severity score:\n")
    for i, finding in enumerate(scored_findings, 1):
        print(f"{i}. [{finding['tool'].upper()}] Score: {finding['score']}/12 ({finding['level'].upper()})")
        print(f"   {finding['reasoning']}\n")


if __name__ == "__main__":
    demo_nuclei_normalization()
    demo_nmap_normalization()
    demo_httpx_normalization()
    demo_exploit_normalization()
    demo_unified_view()
    
    print("\n" + "=" * 80)
    print("SEVERITY SCALE REFERENCE")
    print("=" * 80)
    print("""
    Score Range | Severity Level | Description
    ------------|----------------|------------------------------------------
    0           | INFO           | Informational findings, no immediate risk
    1-3         | LOW            | Minor issues, low exploitability
    4-6         | MEDIUM         | Moderate risk, requires attention
    7-9         | HIGH           | Serious vulnerabilities, high priority
    10-12       | CRITICAL       | Severe issues, immediate action required
    """)
