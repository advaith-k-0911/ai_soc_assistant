"""
Enterprise AI SOC Security Operations Center (SIEM)
Built with Python, Streamlit, Plotly, Groq API, and ReportLab.
"""

import streamlit as st

from config import CUSTOM_CSS, NETWORK_CANVAS_HTML
from utils import generate_sample_logs, run_detections_cached
from analyzer import SOCAnalyzer
from ai import SOCAIAssistant

from components.header import render_header
from components.navigation import render_bottom_navigation
from components.dashboard import render_dashboard
from components.log_explorer import render_log_explorer
from components.threat_matrix import render_threat_matrix
from components.ai_console import render_ai_console
from components.threat_intel import render_threat_intel
from components.reports import render_reports
from components.settings import render_settings
from components.about import render_built_by_page

# Page Configuration
st.set_page_config(
    page_title="Enterprise AI SOC Console | SIEM Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Inject High-Density Enterprise Dark CSS Theme & Cleanup Scripts
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
st.markdown(NETWORK_CANVAS_HTML, unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# SESSION STATE INITIALIZATION
# -----------------------------------------------------------------------------
if "demo_mode" not in st.session_state:
    st.session_state.demo_mode = True

if "logs_df" not in st.session_state:
    st.session_state.logs_df = generate_sample_logs()

if "analyzer" not in st.session_state:
    st.session_state.analyzer = SOCAnalyzer()

if "alerts" not in st.session_state:
    st.session_state.alerts = run_detections_cached(
        st.session_state.logs_df,
        tuple(sorted(st.session_state.analyzer.thresholds.items())),
    )

if "ai_assistant" not in st.session_state:
    st.session_state.ai_assistant = SOCAIAssistant()

if "selected_alert" not in st.session_state:
    st.session_state.selected_alert = st.session_state.alerts[0] if st.session_state.alerts else None

if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

if "investigation_report" not in st.session_state:
    st.session_state.investigation_report = None


# -----------------------------------------------------------------------------
# TOP OPERATIONAL HEADER & LOG INGESTION
# -----------------------------------------------------------------------------
critical_count = sum(1 for a in st.session_state.alerts if a.get("severity") == "Critical")
render_header(
    alerts_count=len(st.session_state.alerts),
    critical_count=critical_count,
    is_demo=st.session_state.demo_mode
)

# -----------------------------------------------------------------------------
# VIEW ROUTER BASED ON BOTTOM NAVIGATION BAR
# -----------------------------------------------------------------------------
active_view = render_bottom_navigation()

if active_view == "Overview":
    render_dashboard(st.session_state.logs_df, st.session_state.alerts, st.session_state.demo_mode)

elif active_view == "Log Explorer":
    render_log_explorer(st.session_state.logs_df)

elif active_view == "Threat Matrix":
    render_threat_matrix(st.session_state.alerts, st.session_state.ai_assistant, st.session_state.logs_df)

elif active_view == "AI Investigation":
    render_ai_console(st.session_state.ai_assistant, st.session_state.logs_df)

elif active_view == "Threat Intelligence":
    render_threat_intel(st.session_state.logs_df)

elif active_view == "PDF Reports":
    render_reports(st.session_state.alerts, st.session_state.logs_df)

elif active_view == "Settings":
    render_settings(st.session_state.ai_assistant)

elif active_view == "Built By":
    render_built_by_page()
