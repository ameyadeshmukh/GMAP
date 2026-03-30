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
    return os.getenv("API_BASE_URL", "http://localhost:8000")


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
        # Frontend-only fallback for current backend stub format:
        # data: {"open_ports": [80, 443, ...]}
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


def _sanitize_job_id(raw_job_id: str) -> str:
    return raw_job_id.strip().strip('"').strip("'")


def _matches_query(finding: Dict[str, Any], query: str) -> bool:
    if not query:
        return True
    q = query.lower()
    searchable = " ".join(
        [
            str(finding.get("tool") or ""),
            str(finding.get("title") or ""),
            str(finding.get("description") or ""),
            str(finding.get("target") or ""),
            str(finding.get("severity") or ""),
            str(finding.get("status") or ""),
            str(finding.get("extra") or ""),
        ]
    ).lower()
    return q in searchable


st.set_page_config(page_title="GMAP Findings Viewer", page_icon="🔎")
st.title("GMAP Findings Viewer")

settings = Settings(api_base_url=_default_api_base_url(), timeout_s=30)

if "findings_job_payload" not in st.session_state:
    st.session_state["findings_job_payload"] = None

job_id = st.text_input("Job ID", placeholder="Paste a job UUID")
left, right = st.columns(2)
with left:
    load_clicked = st.button("Load Findings")
with right:
    refresh_clicked = st.button("Refresh")

clean_job_id = _sanitize_job_id(job_id)

if (load_clicked or refresh_clicked) and not clean_job_id:
    st.warning("Enter a job ID first.")

if (load_clicked or refresh_clicked) and clean_job_id:
    try:
        with st.spinner("Loading findings..."):
            response = api_get(settings, f"/jobs/{clean_job_id}")
        payload = _safe_json(response)
        if response.ok:
            st.session_state["findings_job_payload"] = payload
            st.success(f"Loaded job `{clean_job_id}`")
        else:
            st.error(f"Failed to load job: HTTP {response.status_code}")
            st.json(payload)
    except requests.exceptions.ConnectionError:
        st.error(f"Could not reach the backend at `{settings.api_base_url}`.")
    except requests.exceptions.Timeout:
        st.error("Request timed out.")
    except Exception as e:
        st.error(f"Something went wrong: {e}")

job_payload = st.session_state.get("findings_job_payload")
if isinstance(job_payload, dict):
    findings = _collect_findings(job_payload)
    st.caption(f"Job status: `{job_payload.get('status', 'unknown')}` | Findings: `{len(findings)}`")

    if not findings:
        st.info("No nmap/httpx findings found for this job payload yet.")
    else:
        tool_options = sorted({str(f.get("tool") or "unknown") for f in findings})
        severity_options = sorted({str(f.get("severity") or "unknown") for f in findings})
        status_options = sorted({str(f.get("status") or "unknown") for f in findings})

        c1, c2, c3 = st.columns(3)
        with c1:
            selected_tools = st.multiselect("Tool", options=tool_options, default=tool_options)
        with c2:
            selected_severity = st.multiselect("Severity", options=severity_options, default=severity_options)
        with c3:
            selected_status = st.multiselect("Task Status", options=status_options, default=status_options)
        query = st.text_input(
            "Search findings", placeholder="service, host, status code, title, technology..."
        )

        filtered = [
            f
            for f in findings
            if str(f.get("tool") or "unknown") in selected_tools
            and str(f.get("severity") or "unknown") in selected_severity
            and str(f.get("status") or "unknown") in selected_status
            and _matches_query(f, query)
        ]

        st.write(f"Showing `{len(filtered)}` of `{len(findings)}` findings.")
        table_rows = [
            {
                "id": f["id"],
                "tool": f["tool"],
                "severity": f["severity"],
                "status": f["status"],
                "target": f["target"],
                "title": f["title"],
            }
            for f in filtered
        ]
        st.dataframe(table_rows, use_container_width=True, hide_index=True)

        if filtered:
            labels = [f"{f['tool']} | {f['target']} | {f['title']}" for f in filtered]
            selected_label = st.selectbox("Select finding for details", options=labels)
            selected_finding = filtered[labels.index(selected_label)]

            st.markdown("### Finding Details")
            details_left, details_right = st.columns(2)
            with details_left:
                st.write(f"**Tool:** `{selected_finding['tool']}`")
                st.write(f"**Severity:** `{selected_finding['severity']}`")
                st.write(f"**Status:** `{selected_finding['status']}`")
            with details_right:
                st.write(f"**Target:** `{selected_finding['target']}`")
                st.write(f"**Title:** {selected_finding['title']}")
                st.write(f"**Description:** {selected_finding['description']}")

            st.write("**Parsed fields**")
            st.json(selected_finding.get("extra", {}))
            st.write("**Raw finding payload**")
            st.json(selected_finding.get("raw", {}))
