from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict

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


st.set_page_config(page_title="GMAP Scanner", page_icon="🔒")
st.title("GMAP Scanner")
settings = Settings(api_base_url=_default_api_base_url(), timeout_s=30)

target_url = st.text_input(
    "Scan Target",
    placeholder="e.g. http://192.168.1.10:8080 or 192.168.1.10",
)

if st.button("Submit Scan"):
    if not target_url.strip():
        st.warning("Please enter a target before submitting.")
    else:
        try:
            with st.spinner("Submitting scan..."):
                resp = api_post(settings, "/targets", json={"target_url": target_url})

            payload = _safe_json(resp)
            if resp.ok:
                st.success(f"Job accepted - ID: `{payload.get('job_id')}`")
                st.json(payload)
            else:
                st.error(f"Rejected: HTTP {resp.status_code}")
                st.json(payload)
        except requests.exceptions.ConnectionError:
            st.error(f"Could not reach the backend at `{settings.api_base_url}`.")
        except requests.exceptions.Timeout:
            st.error("Request timed out.")
        except Exception as e:
            st.error(f"Something went wrong: {e}")
