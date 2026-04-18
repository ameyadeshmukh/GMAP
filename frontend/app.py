from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict
import time

import requests
import streamlit as st
from requests import Response


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


def api_post(settings: Settings, path: str, *, json: Dict[str, Any]) -> Response:
    url = f"{settings.api_base_url.rstrip('/')}{path}"
    return _http_session().post(url, json=json, timeout=settings.timeout_s)

def api_get(settings: Settings, path: str) -> Response:
    url = f"{settings.api_base_url.rstrip('/')}{path}"
    return _http_session().get(url, timeout=settings.timeout_s)

# just to display results here for now 
TERMINAL = {"completed", "done", "failed", "error"}



st.set_page_config(page_title="GMAP Scanner", page_icon="🔒")
st.title("GMAP Scanner")
settings = Settings(api_base_url=_default_api_base_url(), timeout_s=30)

if "job_id"          not in st.session_state: st.session_state.job_id          = None
if "job_status"      not in st.session_state: st.session_state.job_status      = None
if "report"          not in st.session_state: st.session_state.report          = None
if "polling"         not in st.session_state: st.session_state.polling         = False
if "review_data"     not in st.session_state: st.session_state.review_data     = None
if "review_decided"  not in st.session_state: st.session_state.review_decided  = False
if "current_phase" not in st.session_state: st.session_state.current_phase = None
if "scan_stats"    not in st.session_state: st.session_state.scan_stats    = {}

target_url = st.text_input(
    "Scan Target",
    placeholder="e.g. http://192.168.1.10:8080 or 192.168.1.10",
)
 
if st.button("Submit Scan", type="primary"):
    if not target_url.strip():
        st.warning("Please enter a target before submitting.")
    else:
        try:
            with st.spinner("Submitting scan..."):
                resp = api_post(settings, "/targets", json={"target_url": target_url})
 
            payload = _safe_json(resp)
            if resp.ok:
                st.session_state.job_id         = payload.get("job_id")
                st.session_state.job_status     = "queued"
                st.session_state.report         = None
                st.session_state.polling        = True
                st.session_state.review_data    = None
                st.session_state.review_decided = False
                st.session_state.current_phase = None
                st.session_state.scan_stats    = {}
                st.success(f"Scan started with Job ID: `{st.session_state.job_id}`")
            else:
                st.error(f"Rejected: HTTP {resp.status_code}")
                st.json(payload)
 
        except requests.exceptions.ConnectionError:
            st.error(f"Could not reach the backend at `{settings.api_base_url}`.")
        except requests.exceptions.Timeout:
            st.error("Request timed out.")
        except Exception as e:
            st.error(f"Something went wrong: {e}")


# Polling and display logic
if st.session_state.job_id:
    try:
        resp = api_get(settings, f"/jobs/{st.session_state.job_id}")
        if resp.ok:
            payload = _safe_json(resp)
            st.session_state.job_status = payload.get("status", "unknown")

            # Pull report out of the graph tool run output
            tools = payload.get("tools", [])
            for tool in tools:
                output = tool.get("output") or {}
                data = output.get("data", {})

                # Update report (even if partial/in-progress)
                report = data.get("report", "")
                if report:
                    st.session_state.report = report

                # Update current phase and stats
                current_phase = data.get("current_phase", "")
                if current_phase:
                    st.session_state.current_phase = current_phase

                st.session_state.scan_stats = {
                    "open_ports": data.get("open_ports", 0),
                    "urls_accessible": data.get("urls_accessible", 0),
                    "vulnerabilities": len(data.get("vulnerabilities", [])),
                }

                # Stop polling when job is terminal and we have final report
                tool_status = output.get("status", "")
                if tool_status == "success":
                    st.session_state.polling = False
                    break
 
    except Exception as e:
        st.error(f"Error checking job: {e}")

    # Show final report when complete
    if st.session_state.report and not st.session_state.polling:
        st.success("**Scan Complete!**")

        # Show final stats
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Open Ports", st.session_state.scan_stats.get("open_ports", 0))
        with col2:
            st.metric("URLs Found", st.session_state.scan_stats.get("urls_accessible", 0))
        with col3:
            st.metric("Vulnerabilities", st.session_state.scan_stats.get("vulnerabilities", 0))

    # ── Human review panel ────────────────────────────────────────────────────
    if st.session_state.job_status == "requires_review" and not st.session_state.review_decided:
        st.divider()

        st.markdown("## 🔍 Human Review Required")
        st.warning("The agent has finished vulnerability detection and requires your approval before proceeding to exploitation. Review the findings below and choose an action.")

        # Fetch review data once
        if st.session_state.review_data is None:
            try:
                r = api_get(settings, f"/jobs/{st.session_state.job_id}/review")
                if r.ok:
                    st.session_state.review_data = _safe_json(r)
            except Exception:
                pass

        review = st.session_state.review_data or {}
        vulns = review.get("vulnerabilities", [])
        msf   = review.get("msf_modules", [])

        SEVERITY_COLOR = {
            "critical": "🔴",
            "high":     "🟠",
            "medium":   "🟡",
            "low":      "🔵",
            "info":     "⚪",
            "unknown":  "⚪",
        }

        col_vulns, col_msf = st.columns(2)

        with col_vulns:
            st.markdown("### Vulnerabilities Found")
            if vulns:
                for v in vulns:
                    severity = (v.get("severity") or "unknown").lower()
                    icon     = SEVERITY_COLOR.get(severity, "⚪")
                    cve      = v.get("cve_id") or v.get("template_id", "N/A")
                    desc     = v.get("description", "")
                    url      = v.get("url", "")
                    with st.container(border=True):
                        st.markdown(f"{icon} **{cve}** `{severity.upper()}`")
                        if desc:
                            st.caption(desc)
                        if url:
                            st.code(url, language=None)
            else:
                st.info("No structured vulnerabilities recorded by nuclei.")

        with col_msf:
            st.markdown("### Proposed Metasploit Modules")
            if msf:
                for m in msf:
                    with st.container(border=True):
                        st.code(m, language=None)
            else:
                st.info("No Metasploit modules proposed.")

        st.divider()
        st.markdown("### What would you like to do?")

        def _submit(decision: str):
            r = api_post(settings, f"/jobs/{st.session_state.job_id}/review",
                         json={"decision": decision})
            if r.ok:
                st.session_state.review_decided = True
                st.session_state.review_data    = None
                st.rerun()
            else:
                st.error(f"Failed to submit decision: {r.text}")

        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown("**Approve Exploitation**")
            st.caption("Run Metasploit modules against the target.")
            if st.button("Approve", type="primary", use_container_width=True):
                _submit("approve")
        with col2:
            st.markdown("**Skip Exploitation**")
            st.caption("Skip to report generation without exploiting.")
            if st.button("Skip", use_container_width=True):
                _submit("skip")
        with col3:
            st.markdown("**Abort Scan**")
            st.caption("Stop immediately and generate report now.")
            if st.button("Abort", use_container_width=True):
                _submit("abort")

    elif st.session_state.job_status == "requires_review" and st.session_state.review_decided:
        st.info("Decision submitted — waiting for scan to resume...")
        time.sleep(3)
        st.rerun()

    elif st.session_state.polling and st.session_state.job_status not in TERMINAL:
        st.info(f"⏳ Scan in progress (status: {st.session_state.job_status})...")
        time.sleep(5)

    # Display scan progress
    if st.session_state.polling and st.session_state.job_status not in TERMINAL:
        # Show current phase with nice formatting
        phase_display = st.session_state.current_phase or "initializing"
        st.info(f"**Scan in progress** (phase: `{phase_display}`)")

        # Show stats in columns
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Open Ports", st.session_state.scan_stats.get("open_ports", 0))
        with col2:
            st.metric("URLs Found", st.session_state.scan_stats.get("urls_accessible", 0))
        with col3:
            st.metric("Vulnerabilities", st.session_state.scan_stats.get("vulnerabilities", 0))

        # Display the report as it builds (live updates)
        if st.session_state.report:
            st.divider()
            st.subheader("Updating Report... (scroll down to view live updates)")
            st.markdown(st.session_state.report)

        time.sleep(3)  # Poll every 3 seconds
        st.rerun()
    elif st.session_state.job_status in TERMINAL and not st.session_state.report:
        st.warning("Scan finished but no report was found.")

    st.divider()
    st.subheader("Final Report:")
    st.markdown(st.session_state.report)
