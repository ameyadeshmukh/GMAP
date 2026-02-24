"""
Job submission UI for Agentic Vulnerability Scanner.
Streamlit frontend aligned to current backend API.

Backend (repo root) currently exposes:
- GET /queue: queues a scan task via Celery and returns a task id + basic result payload.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

import streamlit as st
import requests
from requests import Response


@dataclass(frozen=True)
class Settings:
    api_base_url: str
    timeout_s: int = 30


def _default_api_base_url() -> str:
    # Streamlit supports both environment variables and secrets.toml.
    # Prefer explicit configuration when available.
    try:
        value = st.secrets.get("API_BASE_URL")  # type: ignore[attr-defined]
        if value:
            return str(value)
    except Exception:
        # Streamlit raises if no secrets.toml exists at all; fall back gracefully.
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


def api_get(settings: Settings, path: str, *, params: Optional[Dict[str, Any]] = None) -> Response:
    base = settings.api_base_url.rstrip("/")
    url = f"{base}{path}"
    return _http_session().get(url, params=params, timeout=settings.timeout_s)


st.set_page_config(page_title="Agentic Vulnerability Scanner", page_icon="🔒")
st.title("GMAP Scanner")
with st.sidebar:
    st.header("Settings")
    api_base_url = st.text_input("Backend API base URL", value=_default_api_base_url())
    timeout_s = st.number_input("Request timeout (seconds)", min_value=1, max_value=300, value=30, step=1)
    settings = Settings(api_base_url=api_base_url, timeout_s=int(timeout_s))

    cols = st.columns(2)
    with cols[0]:
        if st.button("Ping API"):
            try:
                r = api_get(settings, "/openapi.json")
                if r.ok:
                    st.success("Backend reachable.")
                else:
                    st.error(f"Backend error: HTTP {r.status_code}")
                    st.json(_safe_json(r))
            except requests.exceptions.ConnectionError:
                st.error(f"Could not reach `{settings.api_base_url}`.")
            except requests.exceptions.Timeout:
                st.error("Ping timed out.")

    with cols[1]:
        st.link_button("Open docs", f"{settings.api_base_url.rstrip('/')}/docs")




target_hint = st.text_input(
    "Target Endpoint URL",
    placeholder="e.g. http://127.0.0.1:8000",
    help="The backend `GET /queue` endpoint is currently hard-coded, so this value is not sent yet.",
)

col_a, col_b = st.columns(2)
with col_a:
    if st.button("Queue scan"):
        try:
            with st.spinner("Queuing scan..."):
                resp = api_get(settings, "/queue")

            if resp.ok:
                payload = _safe_json(resp)
                st.success("Queued successfully.")
                st.json(payload)

                task_id = payload.get("task_id")
                if task_id:
                    st.write("**Task ID:**", task_id)
            else:
                st.error(f"Backend request failed: HTTP {resp.status_code}")
                st.json(_safe_json(resp))
        except requests.exceptions.ConnectionError:
            st.error(f"Could not reach the backend at `{settings.api_base_url}`.")
        except requests.exceptions.Timeout:
            st.error("Request timed out.")
        except Exception as e:
            st.error(f"Something went wrong: {e}")


st.divider()

