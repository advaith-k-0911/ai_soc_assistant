"""
Enterprise Top Navigation Header Bar Component with Log Ingestion Controls
"""

import streamlit as st
from datetime import datetime
from utils import parse_log_file, generate_sample_logs, load_sample_log
from state_helpers import apply_log_dataset


SAMPLE_LOG_OPTIONS = [
    ("auth_bruteforce.log", "Auth Brute-Force"),
    ("powershell_threat.csv", "PowerShell Threat"),
    ("multi_incident.json", "Multi-Incident"),
]


def render_header(alerts_count: int, critical_count: int, is_demo: bool):
    """
    Renders clean, high-density enterprise SIEM top operational header bar with inline log ingestion actions.
    """
    mode_badge = (
        '<span class="soc-status-badge soc-status-demo">DEMO MODE (SYNTHETIC)</span>'
        if is_demo
        else '<span class="soc-status-badge soc-status-live">LIVE ANALYSIS ACTIVE</span>'
    )

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    header_html = f"""
    <div class="soc-header">
        <div class="soc-brand" style="font-family: 'Space Grotesk', sans-serif; font-size: 1.5rem; font-weight: 800; letter-spacing: -0.02em;">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#58A6FF" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <span style="font-size: 1.5rem; font-weight: 800; color: #FFFFFF;">ENTERPRISE SOC CONSOLE</span>
            <span class="soc-brand-tag">v2.4 SIEM</span>
        </div>
        <div style="display: flex; align-items: center; gap: 14px;">
            {mode_badge}
            <div style="font-size: 0.78rem; color: #8B949E; border-left: 1px solid #30363D; padding-left: 14px;">
                Active Threats: <b style="color: #F85149;">{critical_count} Critical</b> / <b style="color: #E6EDF3;">{alerts_count} Total</b>
            </div>
            <div style="font-size: 0.75rem; color: #6E7681; font-family: 'JetBrains Mono', monospace; border-left: 1px solid #30363D; padding-left: 14px;">
                {current_time}
            </div>
        </div>
    </div>
    """
    st.markdown(header_html, unsafe_allow_html=True)

    with st.expander("📥 Log Ingestion & Dataset Controls", expanded=False):
        c1, c2 = st.columns([6, 6])
        with c1:
            st.markdown(
                "<div style='font-size:0.8rem; color:#8B949E; margin-bottom:6px;'>"
                "<b>Upload Live Security Log Stream (CSV, Syslog, TXT, JSON — max 50 MB):</b></div>",
                unsafe_allow_html=True,
            )
            uploaded_file = st.file_uploader(
                "Upload Log Stream",
                type=["csv", "log", "txt", "json"],
                label_visibility="collapsed",
                key="header_log_uploader",
            )
            if uploaded_file is not None:
                try:
                    file_bytes = uploaded_file.read()
                    df_parsed = parse_log_file(file_bytes, uploaded_file.name)
                    if not df_parsed.empty:
                        apply_log_dataset(df_parsed, demo_mode=False)
                        st.success(f"Parsed {len(df_parsed)} events! Switched to Live Analysis.")
                        st.rerun()
                except Exception as e:
                    st.error(f"Log parsing error: {str(e)}")

        with c2:
            st.markdown(
                "<div style='font-size:0.8rem; color:#8B949E; margin-bottom:6px;'>"
                "<b>Reset to Synthetic Demo Dataset:</b></div>",
                unsafe_allow_html=True,
            )
            if st.button("🔄 Reload Synthetic Demo Dataset", use_container_width=True, key="header_demo_reload"):
                with st.spinner("Reloading synthetic demo logs..."):
                    apply_log_dataset(generate_sample_logs(), demo_mode=True)
                    st.toast("Loaded synthetic demo log dataset!", icon="🔄")
                    st.rerun()

        st.markdown(
            "<div style='font-size:0.8rem; color:#8B949E; margin:12px 0 6px 0;'>"
            "<b>Load Bundled Sample Logs:</b></div>",
            unsafe_allow_html=True,
        )
        sample_cols = st.columns(len(SAMPLE_LOG_OPTIONS))
        for col, (filename, label) in zip(sample_cols, SAMPLE_LOG_OPTIONS):
            with col:
                if st.button(f"📂 {label}", use_container_width=True, key=f"sample_{filename}"):
                    try:
                        df_sample = load_sample_log(filename)
                        apply_log_dataset(df_sample, demo_mode=False)
                        st.success(f"Loaded {label} ({len(df_sample)} events).")
                        st.rerun()
                    except Exception as e:
                        st.error(str(e))
