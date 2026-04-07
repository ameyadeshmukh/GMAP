"""
Severity Normalization Layer

Provides unified severity scoring across all pentesting tools (nmap, httpx, nuclei, exploits).
Maps tool-specific findings to a normalized 1-12 scale:
    1-3   = LOW
    4-6   = MEDIUM
    7-9   = HIGH
    10-12 = CRITICAL

This ensures consistent risk assessment and prioritization across the entire pentest workflow.
"""

from typing import Dict, Any, Optional
from enum import Enum


class SeverityLevel(Enum):
    """Normalized severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    INFO = "info"
    UNKNOWN = "unknown"


class SeverityScore:
    """Represents a normalized severity score with metadata"""
    
    def __init__(self, score: int, level: SeverityLevel, source_tool: str, reasoning: str):
        self.score = score  # 1-12 scale
        self.level = level  # LOW, MEDIUM, HIGH, CRITICAL
        self.source_tool = source_tool
        self.reasoning = reasoning
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "normalized_score": self.score,
            "severity_level": self.level.value,
            "source_tool": self.source_tool,
            "reasoning": self.reasoning,
        }


def _score_to_level(score: int) -> SeverityLevel:
    """Convert numeric score (1-12) to severity level"""
    if score <= 0:
        return SeverityLevel.INFO
    elif 1 <= score <= 3:
        return SeverityLevel.LOW
    elif 4 <= score <= 6:
        return SeverityLevel.MEDIUM
    elif 7 <= score <= 9:
        return SeverityLevel.HIGH
    elif score >= 10:
        return SeverityLevel.CRITICAL
    else:
        return SeverityLevel.UNKNOWN


def normalize_nuclei_severity(vuln: Dict[str, Any]) -> SeverityScore:
    """
    Normalize nuclei vulnerability severity to 1-12 scale.
    
    Nuclei provides: critical, high, medium, low, info
    Additional factors: CVSS score, CWE classification
    """
    severity = vuln.get("severity", "unknown").lower()
    cvss_score = vuln.get("cvss_score")
    cve_id = vuln.get("cve_id")
    
    # Base score from nuclei severity
    base_scores = {
        "critical": 11,  # 10-12 range
        "high": 8,       # 7-9 range
        "medium": 5,     # 4-6 range
        "low": 2,        # 1-3 range
        "info": 0,       # informational
        "unknown": 1,    # minimal score
    }
    
    score = base_scores.get(severity, 1)
    
    # Adjust based on CVSS score if available
    if cvss_score:
        try:
            cvss = float(cvss_score)
            # CVSS 9.0-10.0 → boost critical findings
            if cvss >= 9.0 and score >= 10:
                score = 12
            # CVSS 7.0-8.9 → boost high findings
            elif cvss >= 7.0 and score >= 7:
                score = min(score + 1, 9)
        except (ValueError, TypeError):
            pass
    
    # Boost if CVE exists (confirmed vulnerability)
    if cve_id and score > 0:
        score = min(score + 1, 12)
    
    level = _score_to_level(score)
    
    reasoning = f"Nuclei severity: {severity}"
    if cvss_score:
        reasoning += f", CVSS: {cvss_score}"
    if cve_id:
        reasoning += f", CVE: {cve_id}"
    
    return SeverityScore(score, level, "nuclei", reasoning)


def normalize_nmap_severity(port: Dict[str, Any]) -> SeverityScore:
    """
    Normalize nmap port discovery to 1-12 scale.
    
    Open ports are informational but certain services carry higher risk.
    """
    port_num = port.get("port")
    service = (port.get("service") or "").lower()
    version = port.get("version", "")
    
    # High-risk services get elevated scores
    high_risk_services = {
        "telnet": 6,      # unencrypted remote access
        "ftp": 5,         # often misconfigured
        "smb": 7,         # common attack vector
        "rdp": 7,         # remote desktop
        "vnc": 6,         # remote desktop
        "mysql": 5,       # database exposure
        "postgresql": 5,  # database exposure
        "mongodb": 5,     # database exposure
        "redis": 5,       # often no auth
        "elasticsearch": 5,  # often exposed
    }
    
    # Medium-risk services
    medium_risk_services = {
        "ssh": 3,         # secure but still attack surface
        "http": 2,        # web service
        "https": 2,       # web service
        "smtp": 3,        # email
        "dns": 2,         # name resolution
    }
    
    # Check for high-risk services
    for svc, svc_score in high_risk_services.items():
        if svc in service:
            level = _score_to_level(svc_score)
            reasoning = f"Open {service} on port {port_num} (high-risk service)"
            return SeverityScore(svc_score, level, "nmap", reasoning)
    
    # Check for medium-risk services
    for svc, svc_score in medium_risk_services.items():
        if svc in service:
            level = _score_to_level(svc_score)
            reasoning = f"Open {service} on port {port_num}"
            return SeverityScore(svc_score, level, "nmap", reasoning)
    
    # Default: informational (open port)
    reasoning = f"Open port {port_num}/{port.get('protocol', 'tcp')}"
    if service:
        reasoning += f" ({service})"
    
    return SeverityScore(0, SeverityLevel.INFO, "nmap", reasoning)


def normalize_httpx_severity(endpoint: Dict[str, Any]) -> SeverityScore:
    """
    Normalize httpx fingerprinting results to 1-12 scale.
    
    Factors: HTTP status, exposed technologies, server headers
    """
    status_code = endpoint.get("status_code")
    url = endpoint.get("url", "")
    technologies = endpoint.get("technologies", [])
    webserver = endpoint.get("webserver", "")
    
    score = 0
    reasoning_parts = []
    
    # Status code analysis
    if isinstance(status_code, int):
        if status_code == 200:
            score = 1  # accessible endpoint
            reasoning_parts.append(f"HTTP {status_code}")
        elif 300 <= status_code < 400:
            score = 1  # redirect
            reasoning_parts.append(f"HTTP {status_code} redirect")
        elif status_code == 401 or status_code == 403:
            score = 2  # auth required (potential target)
            reasoning_parts.append(f"HTTP {status_code} (auth required)")
        elif status_code == 500:
            score = 4  # server error (potential vuln)
            reasoning_parts.append(f"HTTP {status_code} (server error)")
        elif 400 <= status_code < 500:
            score = 1  # client error
            reasoning_parts.append(f"HTTP {status_code}")
    
    # Technology detection - outdated/risky tech increases score
    risky_tech = {
        "php": 2,
        "wordpress": 3,
        "joomla": 3,
        "drupal": 3,
        "apache": 1,
        "nginx": 1,
        "iis": 2,
        "tomcat": 3,
        "jenkins": 4,
        "phpmyadmin": 5,
    }
    
    for tech in technologies:
        tech_lower = tech.lower()
        for risky, risk_score in risky_tech.items():
            if risky in tech_lower:
                score = max(score, risk_score)
                reasoning_parts.append(f"detected {tech}")
                break
    
    # Admin/sensitive paths
    sensitive_paths = ["/admin", "/login", "/dashboard", "/api", "/phpmyadmin", "/wp-admin"]
    for path in sensitive_paths:
        if path in url.lower():
            score = max(score, 3)
            reasoning_parts.append(f"sensitive path: {path}")
            break
    
    level = _score_to_level(score)
    reasoning = f"{url}: " + ", ".join(reasoning_parts) if reasoning_parts else f"{url}: accessible"
    
    return SeverityScore(score, level, "httpx", reasoning)


def normalize_exploit_severity(exploit_result: Dict[str, Any]) -> SeverityScore:
    """
    Normalize exploitation results to 1-12 scale.
    
    Successful exploits are always critical. Failed attempts are informational.
    """
    success = exploit_result.get("success", False)
    module = exploit_result.get("module", "unknown")
    session_type = exploit_result.get("session_type")
    
    if success:
        # Successful exploitation is always critical
        score = 12
        level = SeverityLevel.CRITICAL
        
        reasoning = f"Successful exploitation: {module}"
        if session_type:
            reasoning += f" (session: {session_type})"
    else:
        # Failed exploitation attempt is informational
        score = 0
        level = SeverityLevel.INFO
        reasoning = f"Failed exploitation attempt: {module}"
    
    return SeverityScore(score, level, "metasploit", reasoning)


def normalize_finding(finding: Dict[str, Any], tool: str) -> SeverityScore:
    """
    Main entry point: normalize any finding from any tool.
    
    Args:
        finding: The finding dict from the tool
        tool: Tool name ("nmap", "httpx", "nuclei", "metasploit")
    
    Returns:
        SeverityScore with normalized 1-12 score and severity level
    """
    tool_lower = tool.lower()
    
    if tool_lower == "nuclei":
        return normalize_nuclei_severity(finding)
    elif tool_lower == "nmap":
        return normalize_nmap_severity(finding)
    elif tool_lower == "httpx":
        return normalize_httpx_severity(finding)
    elif tool_lower in ["metasploit", "msf", "exploit"]:
        return normalize_exploit_severity(finding)
    else:
        # Unknown tool - return minimal score
        return SeverityScore(
            score=1,
            level=SeverityLevel.UNKNOWN,
            source_tool=tool,
            reasoning=f"Unknown tool: {tool}"
        )


def get_severity_distribution(findings: list, tool: str) -> Dict[str, int]:
    """
    Get distribution of severity levels for a list of findings.
    
    Returns:
        Dict with counts: {"critical": 2, "high": 5, "medium": 10, "low": 3, "info": 20}
    """
    distribution = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }
    
    for finding in findings:
        severity_score = normalize_finding(finding, tool)
        distribution[severity_score.level.value] += 1
    
    return distribution
