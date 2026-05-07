from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict
from tools.vulhub_containers import is_vulhub_running, get_vulhub_scenarios, resolve_scenario_path, launch_vulhub, BASE_DIR, VULHUB_DIR
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
    return os.getenv("API_BASE_URL", "https://gmap-backend-1014661949781.us-central1.run.app")


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
if "current_phase"   not in st.session_state: st.session_state.current_phase   = None
if "scan_stats"      not in st.session_state: st.session_state.scan_stats      = {}
if "action_log"      not in st.session_state: st.session_state.action_log      = []

target_url = st.text_input(
    "Scan Target",
    placeholder="e.g. http://192.168.1.10:8080",
)
# ── Submit scan ───────────────────────────────────────────────────────────────
if st.button("Submit Scan", type="primary"):
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
                st.session_state.current_phase  = None
                st.session_state.scan_stats     = {}
                st.session_state.action_log     = []
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

# ── Polling and display logic ─────────────────────────────────────────────────
if st.session_state.job_id:
    try:
        resp = api_get(settings, f"/jobs/{st.session_state.job_id}")
        if resp.ok:
            payload = _safe_json(resp)
            st.session_state.job_status = payload.get("status", "unknown")

            tools = payload.get("tools", [])
            for tool in tools:
                output = tool.get("output") or {}
                data = output.get("data", {})

                report = data.get("report", "")
                if report:
                    st.session_state.report = report

                action_log = data.get("action_log", [])
                if action_log:
                    st.session_state.action_log = action_log

                current_phase = data.get("current_phase", "")
                if current_phase:
                    st.session_state.current_phase = current_phase

                st.session_state.scan_stats = {
                    "open_ports": data.get("open_ports", 0),
                    "urls_accessible": data.get("urls_accessible", 0),
                    "vulnerabilities": len(data.get("vulnerabilities", [])),
                }

                tool_status = output.get("status", "")
                if tool_status == "success":
                    st.session_state.polling = False
                    break

    except Exception as e:
        st.error(f"Error checking job: {e}")

    # ── Scan complete ─────────────────────────────────────────────────────────
    if (st.session_state.report and
            not st.session_state.polling and
            st.session_state.job_status not in ["requires_review"]):

        st.success("✅ **Scan Complete!**")

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Open Ports", st.session_state.scan_stats.get("open_ports", 0))
        with col2:
            st.metric("URLs Found", st.session_state.scan_stats.get("urls_accessible", 0))
        with col3:
            st.metric("Vulnerabilities", st.session_state.scan_stats.get("vulnerabilities", 0))

        st.divider()
        if st.button("📄 View Report", use_container_width=True, type="primary"):
            st.switch_page("pages/Findings_Viewer.py")

        # ── Vulnerabilities with NVD links ────────────────────────────────────
        st.divider()
        st.subheader("🔍 Vulnerabilities Found")

        if st.session_state.review_data is None:
            try:
                r = api_get(settings, f"/jobs/{st.session_state.job_id}/review")
                if r.ok:
                    st.session_state.review_data = _safe_json(r)
            except Exception:
                pass

        review = st.session_state.review_data or {}
        vulns = review.get("vulnerabilities", [])

        SEVERITY_COLOR = {
            "critical": "🔴",
            "high":     "🟠",
            "medium":   "🟡",
            "low":      "🔵",
            "info":     "⚪",
            "unknown":  "⚪",
        }

        if vulns:
            for v in vulns:
                severity = (v.get("severity") or "unknown").lower()
                icon = SEVERITY_COLOR.get(severity, "⚪")
                cve = v.get("cve_id") or v.get("template_id", "N/A")
                name = v.get("name", "")
                desc = v.get("description", "")
                url = v.get("url", "")
                nvd_link = v.get("nvd_link")

                with st.container(border=True):
                    col_title, col_badge = st.columns([4, 1])
                    with col_title:
                        st.markdown(f"{icon} **{cve}**" + (f" — {name}" if name else ""))
                    with col_badge:
                        st.markdown(f"`{severity.upper()}`")
                    if desc:
                        st.caption(desc)
                    col_url, col_link = st.columns([3, 1])
                    with col_url:
                        if url:
                            st.code(url, language=None)
                    with col_link:
                        if nvd_link:
                            st.link_button("🔗 NVD Details", nvd_link)
        else:
            st.info("No vulnerabilities recorded.")

        # ── Agent Action Log ──────────────────────────────────────────────────
        st.divider()
        st.subheader("🤖 Agent Action Log")
        if st.session_state.action_log:
            for entry in st.session_state.action_log:
                st.text(entry)
        else:
            st.info("No action log entries recorded.")

    # ── Scan in progress ──────────────────────────────────────────────────────
    if st.session_state.polling and st.session_state.job_status not in TERMINAL:
        phase_display = st.session_state.current_phase or "initializing"
        st.info(f"⌛ **Scan in progress** (phase: `{phase_display}`)")

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Open Ports", st.session_state.scan_stats.get("open_ports", 0))
        with col2:
            st.metric("URLs Found", st.session_state.scan_stats.get("urls_accessible", 0))
        with col3:
            st.metric("Vulnerabilities", st.session_state.scan_stats.get("vulnerabilities", 0))

        if st.session_state.action_log:
            st.divider()
            st.subheader("🤖 Agent Action Log")
            for entry in st.session_state.action_log:
                st.text(entry)

        if st.session_state.report:
            st.divider()
            if st.button("📄 View Report", use_container_width=True, type="primary"):
                st.switch_page("pages/Findings_Viewer.py")

        time.sleep(3)
        st.rerun()

    elif st.session_state.job_status in TERMINAL and not st.session_state.report:
        st.warning("Scan finished but no report was found.")