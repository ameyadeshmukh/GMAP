from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict
from tools.vulhub_containers import is_vulhub_running, get_vulhub_scenarios,resolve_scenario_path, launch_vulhub, BASE_DIR, VULHUB_DIR
import subprocess
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



st.set_page_config(page_title="GMAP Scanner", page_icon="🔒", layout="wide")
st.title("GMAP Scanner")
settings = Settings(api_base_url=_default_api_base_url(), timeout_s=30)

# ── Scan history sidebar ──────────────────────────────────────────────────────
with st.sidebar:
    st.header("Scan History")
    if st.button("Refresh", use_container_width=True):
        st.rerun()
    try:
        hist_resp = api_get(settings, "/jobs")
        if hist_resp.ok:
            jobs = hist_resp.json() if isinstance(hist_resp.json(), list) else []
            if not jobs:
                st.caption("No scans yet.")
            for j in jobs:
                jid    = j.get("job_id", "")
                status = j.get("status", "unknown")
                ts     = (j.get("started_at") or "")[:16].replace("T", " ")
                status_icon = {"completed": "✅", "failed": "❌", "running": "⏳",
                               "requires_review": "👁️", "queued": "🕐"}.get(status, "•")
                label = f"{status_icon} `{jid[:8]}…` {ts}"
                if st.button(label, key=f"hist_{jid}", use_container_width=True):
                    st.session_state.job_id         = jid
                    st.session_state.job_status     = status
                    st.session_state.report         = None
                    st.session_state.polling        = status not in TERMINAL
                    st.session_state.review_data    = None
                    st.session_state.review_decided = False
                    st.session_state.current_phase  = None
                    st.session_state.scan_stats     = {}
                    st.rerun()
    except Exception:
        st.caption("Could not load history.")

if "job_id"          not in st.session_state: st.session_state.job_id          = None
if "job_status"      not in st.session_state: st.session_state.job_status      = None
if "report"          not in st.session_state: st.session_state.report          = None
if "polling"         not in st.session_state: st.session_state.polling         = False
if "review_data"     not in st.session_state: st.session_state.review_data     = None
if "review_decided"  not in st.session_state: st.session_state.review_decided  = False
if "current_phase" not in st.session_state: st.session_state.current_phase = None
if "scan_stats"    not in st.session_state: st.session_state.scan_stats    = {}

scenarios = get_vulhub_scenarios()

scenario_names = ["Select Option"] + list(scenarios.keys())

selected = st.selectbox(
    "Select Vulhub Environment",
    scenario_names,
    index=0
)

target_url = ""

# manually enter target url
if selected == "Select Option":
    st.info("Select a Vulhub scenario or enter a custom target.")

    target_url = st.text_input(
        "Scan Target",
        placeholder="e.g. http://192.168.1.10:8080",
    )

# select vulhub containers from our catalog
else:
    rule = scenarios[selected]
    selected_running = False


    if is_vulhub_running(rule):
        st.success("Container running")
        selected_running = True
    else:
        st.warning("Container not running")
        selected_running = False

    col1, col2 = st.columns(2)

    if selected_running == False:
        with col1:
            if st.button("Start Vulhub Container"):
                ok, msg = launch_vulhub(rule)

                if ok:
                    st.success(msg)
                    time.sleep(2)
                    st.rerun()
                else:
                    st.error(msg)
    if selected_running == True:
        with col2:
            if st.button("Stop Container"):
                scenario_path = resolve_scenario_path(rule)

                if scenario_path:
                    subprocess.Popen(
                        ["docker", "compose", "down"],
                        cwd=scenario_path
                    )
                    st.warning("Stopped container")
                    time.sleep(2)
                    st.rerun()

    # target url from vulhub container
    if rule.port:
        target_url = f"http://127.0.0.1:{rule.port}"
        st.caption(f"Selected target URL: {target_url}")
    else:
        target_url = st.text_input("Scan Target)")
 
if st.button("Submit Scan", type="primary"):
    if selected != "Select Option":
        rule = scenarios[selected]

        if not is_vulhub_running(rule):
            st.error("Vulhub container is not running. Start it before scanning.")
            st.stop()
    if not target_url.strip():
        st.warning("Please enter a target before submitting.")
        st.stop()
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

    # Show final report when complete (not during review or polling)
    if (st.session_state.report and
        not st.session_state.polling and
        st.session_state.job_status not in ["requires_review"]):

        st.success("✅ **Scan Complete!**")

        # Show final stats
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Open Ports", st.session_state.scan_stats.get("open_ports", 0))
        with col2:
            st.metric("URLs Found", st.session_state.scan_stats.get("urls_accessible", 0))
        with col3:
            st.metric("Vulnerabilities", st.session_state.scan_stats.get("vulnerabilities", 0))

        st.divider()
        st.subheader("📄 Final Report:")
        st.markdown(st.session_state.report)

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

    # Display scan progress
    if st.session_state.polling and st.session_state.job_status not in TERMINAL:
        PHASES = ["discovery", "fingerprinting", "vuln_detection", "review", "exploitation", "documentation"]
        PHASE_LABELS = {
            "discovery":      "Discovery",
            "fingerprinting": "Fingerprinting",
            "vuln_detection": "Vuln Detection",
            "review":         "Human Review",
            "exploitation":   "Exploitation",
            "documentation":  "Report",
        }
        current = st.session_state.current_phase or ""
        current_idx = PHASES.index(current) if current in PHASES else -1

        st.markdown("**Scan Progress**")
        cols = st.columns(len(PHASES))
        for i, phase in enumerate(PHASES):
            with cols[i]:
                if i < current_idx:
                    st.success(PHASE_LABELS[phase])
                elif i == current_idx:
                    st.info(f"⏳ {PHASE_LABELS[phase]}")
                else:
                    st.markdown(f"<div style='color:grey;text-align:center'>{PHASE_LABELS[phase]}</div>", unsafe_allow_html=True)

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Open Ports", st.session_state.scan_stats.get("open_ports", 0))
        with col2:
            st.metric("URLs Found", st.session_state.scan_stats.get("urls_accessible", 0))
        with col3:
            st.metric("Vulnerabilities", st.session_state.scan_stats.get("vulnerabilities", 0))

        if st.session_state.report:
            st.divider()
            st.subheader("📄 Updating Report...")
            st.markdown(st.session_state.report)

        time.sleep(3)
        st.rerun()

    elif st.session_state.job_status in TERMINAL and not st.session_state.report:
        st.warning("Scan finished but no report was found.")
