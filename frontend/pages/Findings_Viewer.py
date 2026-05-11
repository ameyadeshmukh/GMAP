from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List

import requests
import streamlit as st
from requests import Response

NMAP_TOOL_ID = "00000000-0000-0000-0000-000000000002"
NUCLEI_TOOL_ID = "00000000-0000-0000-0000-000000000003"
HTTPX_TOOL_ID = "00000000-0000-0000-0000-000000000004"

@dataclass(frozen=True)
class Settings:
    api_base_url: str
    timeout_s: int = 30


def _default_api_base_url() -> str:
    try:
        value = st.secrets.get("API_BASE_URL")  # type: ignore[attr-defined]
        if value:
            return str(value)
    except Exception:
        pass
    return os.getenv("API_BASE_URL", "https://gmapxyz.fastapicloud.dev")


@st.cache_resource
def _http_session() -> requests.Session:
    return requests.Session()


def _safe_json(resp: Response) -> Dict[str, Any]:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {"data": data}
    except Exception:
        return {"raw": resp.text}


def api_get(settings: Settings, path: str) -> Response:
    url = f"{settings.api_base_url.rstrip('/')}{path}"
    return _http_session().get(url, timeout=settings.timeout_s)


# ── Severity normalization functions ──────────────────────────────────────────

def _tool_name_from_entry(entry: Dict[str, Any]) -> str:
    tool_id = str(entry.get("tool_id") or "").lower()
    if tool_id == NMAP_TOOL_ID:
        return "nmap"
    if tool_id == HTTPX_TOOL_ID:
        return "httpx"
    if tool_id == NUCLEI_TOOL_ID:
        return "nuclei"

    output = entry.get("output") or {}
    if not isinstance(output, dict):
        return "unknown"

    scan_obj = output.get("scan")
    if isinstance(scan_obj, dict) and scan_obj.get("tool"):
        return str(scan_obj["tool"]).lower()
    if output.get("tool_name"):
        return str(output["tool_name"]).lower()
    return "unknown"


def _payload_from_output(output: Dict[str, Any]) -> Dict[str, Any]:
    data = output.get("data")
    if isinstance(data, dict):
        return data
    return output


def _severity_for_http_status(status_code: Any) -> str:
    if not isinstance(status_code, int):
        return "unknown"
    if status_code >= 500:
        return "medium"
    if status_code >= 400:
        return "low"
    return "info"


def _normalize_nmap_findings(tool_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    output = tool_entry.get("output")
    if not isinstance(output, dict):
        return []

    payload = _payload_from_output(output)
    findings: List[Dict[str, Any]] = []
    hosts = payload.get("hosts")
    if not isinstance(hosts, list):
        open_ports = payload.get("open_ports")
        if isinstance(open_ports, list) and open_ports:
            input_payload = tool_entry.get("input") if isinstance(tool_entry.get("input"), dict) else {}
            target = str(input_payload.get("target") or "unknown")
            for port in open_ports:
                findings.append(
                    {
                        "id": f"nmap-{target}-{port}-tcp",
                        "tool": "nmap",
                        "severity": "info",
                        "target": target,
                        "title": f"Open port {port}/tcp on {target}",
                        "description": "Port reported open by nmap task output.",
                        "status": str(tool_entry.get("status") or "unknown"),
                        "extra": {
                            "port": port,
                            "protocol": "tcp",
                            "source": "fallback_open_ports",
                        },
                        "raw": payload,
                    }
                )
        return findings

    for host in hosts:
        if not isinstance(host, dict):
            continue
        ip = str(host.get("ip") or "unknown")
        hostnames = host.get("hostnames") or []
        hostnames_text = ", ".join([str(h) for h in hostnames if h]) if isinstance(hostnames, list) else ""
        ports = host.get("ports") or []
        if not isinstance(ports, list):
            continue

        for port_info in ports:
            if not isinstance(port_info, dict):
                continue
            service = port_info.get("service") if isinstance(port_info.get("service"), dict) else {}
            port = port_info.get("port")
            protocol = str(port_info.get("protocol") or "tcp")
            service_name = str(service.get("name") or "unknown")
            service_product = str(service.get("product") or "")
            service_version = str(service.get("version") or "")
            description = f"Service: {service_name}"
            if service_product:
                description += f", product: {service_product}"
            if service_version:
                description += f", version: {service_version}"

            findings.append(
                {
                    "id": f"nmap-{ip}-{port}-{protocol}",
                    "tool": "nmap",
                    "severity": "info",
                    "target": ip,
                    "title": f"Open port {port}/{protocol} on {ip}",
                    "description": description,
                    "status": str(tool_entry.get("status") or "unknown"),
                    "extra": {
                        "hostnames": hostnames_text,
                        "port_state": port_info.get("state"),
                        "service_name": service_name,
                        "service_product": service_product,
                        "service_version": service_version,
                    },
                    "raw": port_info,
                }
            )
    return findings


def _normalize_httpx_findings(tool_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    output = tool_entry.get("output")
    if not isinstance(output, dict):
        return []

    payload = _payload_from_output(output)
    endpoints = payload.get("endpoints")
    if not isinstance(endpoints, list):
        return []

    findings: List[Dict[str, Any]] = []
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        url = str(endpoint.get("url") or "unknown")
        status_code = endpoint.get("status_code")
        technologies = endpoint.get("technologies")
        tech_list = technologies if isinstance(technologies, list) else []
        findings.append(
            {
                "id": f"httpx-{url}",
                "tool": "httpx",
                "severity": _severity_for_http_status(status_code),
                "target": url,
                "title": f"HTTP endpoint {status_code} - {url}",
                "description": (
                    f"Title: {endpoint.get('title') or 'N/A'}, "
                    f"Web server: {endpoint.get('webserver') or 'N/A'}"
                ),
                "status": str(tool_entry.get("status") or "unknown"),
                "extra": {
                    "status_code": status_code,
                    "scheme": endpoint.get("scheme"),
                    "host": endpoint.get("host"),
                    "port": endpoint.get("port"),
                    "content_type": endpoint.get("content_type"),
                    "content_length": endpoint.get("content_length"),
                    "webserver": endpoint.get("webserver"),
                    "technologies": ", ".join([str(t) for t in tech_list]),
                },
                "raw": endpoint,
            }
        )
    return findings


def _collect_findings(job_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    tools = job_payload.get("tools")
    if not isinstance(tools, list):
        return findings

    for tool_entry in tools:
        if not isinstance(tool_entry, dict):
            continue
        tool_name = _tool_name_from_entry(tool_entry)
        if tool_name == "nmap":
            findings.extend(_normalize_nmap_findings(tool_entry))
        elif tool_name == "httpx":
            findings.extend(_normalize_httpx_findings(tool_entry))
    return findings


# ── Page UI ───────────────────────────────────────────────────────────────────

st.set_page_config(page_title="GMAP Findings Viewer", page_icon="🔎")
st.title("GMAP Findings Viewer")

settings = Settings(api_base_url=_default_api_base_url(), timeout_s=30)

# Get the report from session state (shared with app.py)
report = st.session_state.get("report", "")

if report:
    st.subheader("📄 Penetration Testing Report")
    st.markdown(report)
else:
    st.info("No report available yet. Start a scan from the main page to generate a report.")
    st.page_link("app.py", label="Go to Scanner", icon="🔒")
