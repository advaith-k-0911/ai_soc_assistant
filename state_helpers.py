"""
Shared session-state helpers for log ingestion and detection reprocessing.
"""

from pathlib import Path
from typing import Optional

import pandas as pd
import streamlit as st

from analyzer import SOCAnalyzer
from utils import run_detections_cached


def apply_log_dataset(df: pd.DataFrame, demo_mode: bool = False) -> None:
    """Update session state after loading or uploading a new log dataset."""
    st.session_state.demo_mode = demo_mode
    st.session_state.logs_df = df
    st.session_state.alerts = run_detections_cached(df, _thresholds_key())
    st.session_state.selected_alert = st.session_state.alerts[0] if st.session_state.alerts else None
    st.session_state.investigation_report = None
    st.session_state.chat_history = []


def reprocess_current_logs() -> None:
    """Re-run detections on the current log dataset (e.g. after threshold change)."""
    st.session_state.alerts = run_detections_cached(st.session_state.logs_df, _thresholds_key())
    st.session_state.selected_alert = st.session_state.alerts[0] if st.session_state.alerts else None
    st.session_state.investigation_report = None


def _thresholds_key() -> tuple:
    analyzer: SOCAnalyzer = st.session_state.analyzer
    return tuple(sorted(analyzer.thresholds.items()))


def save_api_key_to_env(api_key: str) -> None:
    """Persist Groq API key to the project .env file."""
    env_path = Path(__file__).parent / ".env"
    lines: list[str] = []
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines()

    updated = False
    new_lines: list[str] = []
    for line in lines:
        if line.startswith("GROQ_API_KEY="):
            new_lines.append(f"GROQ_API_KEY={api_key}")
            updated = True
        else:
            new_lines.append(line)

    if not updated:
        new_lines.append(f"GROQ_API_KEY={api_key}")

    env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


def ensure_investigation_report(ai_assistant, logs_df: pd.DataFrame) -> Optional[dict]:
    """Lazily generate the AI investigation report when an alert is selected."""
    if not st.session_state.selected_alert:
        return None
    if st.session_state.investigation_report is not None:
        return st.session_state.investigation_report

    with st.spinner("Generating grounded AI incident report..."):
        st.session_state.investigation_report = ai_assistant.analyze_incident(
            st.session_state.selected_alert, logs_df
        )
    return st.session_state.investigation_report
