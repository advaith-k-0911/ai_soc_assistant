"""
System Settings & Rule Threshold Tuning Component
"""

import os
import streamlit as st
from config import THRESHOLDS, BUSINESS_HOURS
from ai import SOCAIAssistant
from state_helpers import reprocess_current_logs, save_api_key_to_env


def render_settings(ai_assistant):
    """
    Renders API credentials configuration and detection rule sensitivity thresholds.
    """
    st.markdown("""
        <div class="soc-panel-title" style="margin-bottom: 12px;">SYSTEM CONFIGURATION & SENSITIVITY TUNING</div>
    """, unsafe_allow_html=True)

    st.markdown("<h5 style='font-size:0.85rem; color:#8B949E; text-transform:uppercase;'>1. AI ENGINE API CREDENTIALS</h5>", unsafe_allow_html=True)

    current_key = os.getenv("GROQ_API_KEY", "")
    groq_key_input = st.text_input("Groq API Key (Llama-3.3-70B model provider):", value=current_key, type="password")

    if st.button("Save API Credentials"):
        os.environ["GROQ_API_KEY"] = groq_key_input
        save_api_key_to_env(groq_key_input)
        st.session_state.ai_assistant = SOCAIAssistant(api_key=groq_key_input)
        st.success("API credentials saved to .env and applied.")
        st.rerun()

    st.markdown("<hr style='border-color:#21262D; margin: 20px 0;'/>", unsafe_allow_html=True)

    st.markdown("<h5 style='font-size:0.85rem; color:#8B949E; text-transform:uppercase;'>2. DETECTION ENGINE RULE THRESHOLDS</h5>", unsafe_allow_html=True)

    analyzer = st.session_state.analyzer
    bf_thresh = st.slider(
        "Brute Force Failure Attempts Threshold:",
        min_value=3, max_value=15,
        value=analyzer.thresholds["brute_force_attempts"],
    )
    ps_thresh = st.slider(
        "Port Scanning Distinct Ports Threshold:",
        min_value=3, max_value=25,
        value=analyzer.thresholds["port_scan_distinct_ports"],
    )
    it_thresh = st.slider(
        "Impossible Travel Max Window (Hours):",
        min_value=1, max_value=6,
        value=analyzer.thresholds["impossible_travel_max_hours"],
    )
    bh_start = st.slider(
        "Business Hours Start (24h):",
        min_value=0, max_value=23,
        value=BUSINESS_HOURS["start"],
    )
    bh_end = st.slider(
        "Business Hours End (24h):",
        min_value=1, max_value=24,
        value=BUSINESS_HOURS["end"],
    )

    if st.button("Apply Threshold Configurations"):
        analyzer.thresholds["brute_force_attempts"] = bf_thresh
        analyzer.thresholds["port_scan_distinct_ports"] = ps_thresh
        analyzer.thresholds["impossible_travel_max_hours"] = it_thresh
        BUSINESS_HOURS["start"] = bh_start
        BUSINESS_HOURS["end"] = bh_end
        reprocess_current_logs()
        st.success("Thresholds updated and detections re-evaluated.")
        st.rerun()

    st.markdown("<hr style='border-color:#21262D; margin: 20px 0;'/>", unsafe_allow_html=True)

    st.markdown("<h5 style='font-size:0.85rem; color:#8B949E; text-transform:uppercase;'>3. SYSTEM COLLECTOR & AI HEALTH STATUS</h5>", unsafe_allow_html=True)

    ai_status = (
        "<span style='color:#3FB950;'>🟢 Groq API Connected (Llama-3.3-70B)</span>"
        if ai_assistant.is_groq_active()
        else "<span style='color:#D29922;'>🟡 Offline Heuristic Engine Active</span>"
    )

    st.markdown(f"""
        <div class="soc-panel">
            <div style="font-size: 0.8rem; color: #8B949E; margin-bottom: 6px;"><b>AI Inference Engine Status:</b> {ai_status}</div>
            <div style="font-size: 0.8rem; color: #8B949E; margin-bottom: 6px;"><b>Log Normalization Parser:</b> <span style="color:#3FB950;">🟢 Operational (Syslog, CSV, JSON)</span></div>
            <div style="font-size: 0.8rem; color: #8B949E;"><b>Rule Correlation Engine:</b> <span style="color:#3FB950;">🟢 Active (9 Vectors Monitored)</span></div>
        </div>
    """, unsafe_allow_html=True)
