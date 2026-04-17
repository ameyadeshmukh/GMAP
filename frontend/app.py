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


# ── Polling loop ──────────────────────────────────────────────────────────────
if st.session_state.job_id and st.session_state.report is None:
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
                    st.session_state.report  = report
                    st.session_state.polling = False
                    break

    except Exception as e:
        st.error(f"Error checking job: {e}")

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
        st.rerun()
    elif st.session_state.job_status in TERMINAL and not st.session_state.report:
        st.warning("Scan finished but no report was found.")


# ── Report ────────────────────────────────────────────────────────────────────
if st.session_state.report:
    st.divider()
    st.markdown(st.session_state.report)
