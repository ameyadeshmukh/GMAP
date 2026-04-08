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

if "job_id"     not in st.session_state: st.session_state.job_id     = None
if "job_status" not in st.session_state: st.session_state.job_status = None
if "report"     not in st.session_state: st.session_state.report     = None
if "polling"    not in st.session_state: st.session_state.polling    = False

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
                st.session_state.job_id     = payload.get("job_id")
                st.session_state.job_status = "queued"
                st.session_state.report     = None
                st.session_state.polling    = True
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


if st.session_state.job_id and st.session_state.report is None:
    try:
        resp = api_get(settings, f"/jobs/{st.session_state.job_id}")
        if resp.ok:
            payload = _safe_json(resp)
            st.session_state.job_status = payload.get("status", "unknown")
 
            # pull report out of the graph tool run output
            tools = payload.get("tools", [])
            for tool in tools:
                output = tool.get("output") or {}
                data = output.get("data", {})
                report = data.get("report", "")
                if report:
                    st.session_state.report = report
                    st.session_state.polling = False
                    break
 
    except Exception as e:
        st.error(f"Error checking job: {e}")
 
    if st.session_state.polling and st.session_state.job_status not in TERMINAL:
        st.info(f"⏳ Scan in progress (status: {st.session_state.job_status})...")
        time.sleep(5)
        st.rerun()
    elif st.session_state.job_status in TERMINAL and not st.session_state.report:
        st.warning("Scan finished but no report was found.")
 
# show report 
if st.session_state.report:
    st.divider()
    st.markdown(st.session_state.report)
