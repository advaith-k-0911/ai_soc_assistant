"""
Correlated Threat Matrix & Incident Drawer Component
"""

import html
import pandas as pd
import streamlit as st
from components.styles import get_severity_badge_html


def render_threat_matrix(alerts: list, ai_assistant, logs_df: pd.DataFrame):
    """
    Renders active correlated alerts matrix and side incident details drawer.
    """
    st.markdown("""
        <div class="soc-panel-title" style="margin-bottom: 12px;">CORRELATED THREAT MATRIX & INCIDENT DRAWER</div>
    """, unsafe_allow_html=True)

    if not alerts:
        st.success("No active security threats correlated.")
        return

    col1, col2 = st.columns([7, 5])

    with col1:
        st.markdown("<h5 style='font-size:0.85rem; color:#8B949E; text-transform:uppercase;'>ACTIVE CORRELATED ALERTS</h5>", unsafe_allow_html=True)
        
        for idx, alert in enumerate(alerts):
            sev = alert.get("severity", "High")
            badge_html = get_severity_badge_html(sev)

            # Sentinel: Escape all interpolated user inputs in HTML payload to prevent XSS
            with st.expander(f"[{alert['alert_id']}] {alert['title']} — ({sev.upper()})", expanded=(idx == 0)):
                st.markdown(f"""
                    <div style="font-size: 0.82rem; margin-bottom: 8px;">
                        <b>Severity:</b> {badge_html} | <b>Confidence:</b> <span style="color:#58A6FF; font-family:'JetBrains Mono';">{alert['confidence']}%</span>
                    </div>
                    <div style="font-size: 0.8rem; color: #8B949E; font-family: 'JetBrains Mono', monospace; margin-bottom: 8px;">
                        Source IP: <span style="color:#58A6FF;">{html.escape(str(alert['src_ip']))}</span> | User: <span>{html.escape(str(alert['username']))}</span> | Asset: {html.escape(str(alert['affected_asset']))}
                    </div>
                    <div style="font-size: 0.8rem; color: #C9D1D9; margin-bottom: 8px;">
                        <b>MITRE ATT&CK:</b> {html.escape(str(alert['mitre_id']))} - <i>{html.escape(str(alert['mitre_name']))}</i> ({html.escape(str(alert['tactic']))})
                    </div>
                    <div style="font-size: 0.78rem; color: #8B949E; margin-bottom: 12px;">
                        {html.escape(str(alert['description']))}
                    </div>
                """, unsafe_allow_html=True)

                if st.button(f"🔍 Inspect in AI Investigation Console", key=f"btn_inspect_{alert['alert_id']}"):
                    st.session_state.selected_alert = alert
                    st.session_state.investigation_report = None
                    st.rerun()

    with col2:
        st.markdown("<h5 style='font-size:0.85rem; color:#8B949E; text-transform:uppercase;'>INCIDENT DETAILS DRAWER</h5>", unsafe_allow_html=True)
        
        selected = st.session_state.selected_alert
        if selected:
            badge_html = get_severity_badge_html(selected.get("severity", "High"))
            # Sentinel: Escape all interpolated user inputs in HTML payload to prevent XSS
            st.markdown(f"""
                <div class="soc-panel">
                    <div style="font-size: 0.95rem; font-weight: 700; color: #F0F6FC; margin-bottom: 6px;">
                        {html.escape(str(selected['title']))}
                    </div>
                    <div style="margin-bottom: 12px;">
                        {badge_html}
                        <span style="font-size: 0.75rem; color: #8B949E; margin-left: 8px; font-family:'JetBrains Mono';">
                            ID: {html.escape(str(selected['alert_id']))} | Confidence: {selected['confidence']}%
                        </span>
                    </div>
                    <div style="font-size: 0.8rem; color: #8B949E; margin-bottom: 4px;">
                        <b>Source IP:</b> <span style="font-family:'JetBrains Mono'; color:#58A6FF;">{html.escape(str(selected['src_ip']))}</span>
                    </div>
                    <div style="font-size: 0.8rem; color: #8B949E; margin-bottom: 4px;">
                        <b>Target Account:</b> {html.escape(str(selected['username']))}
                    </div>
                    <div style="font-size: 0.8rem; color: #8B949E; margin-bottom: 4px;">
                        <b>Destination Asset:</b> {html.escape(str(selected['affected_asset']))}
                    </div>
                    <div style="font-size: 0.8rem; color: #8B949E; margin-bottom: 12px;">
                        <b>MITRE Technique:</b> {html.escape(str(selected['mitre_id']))} ({html.escape(str(selected['mitre_name']))})
                    </div>
                    <hr style="border-color:#21262D; margin: 10px 0;"/>
                    <div style="font-size: 0.78rem; font-weight: 600; color: #3FB950; text-transform: uppercase; margin-bottom: 4px;">RECOMMENDED MITIGATION</div>
                    <div style="font-size: 0.8rem; color: #C9D1D9;">
                        {html.escape(str(selected['recommendation']))}
                    </div>
                </div>
            """, unsafe_allow_html=True)

            st.markdown("<h6 style='font-size:0.78rem; color:#8B949E; text-transform:uppercase;'>EVIDENCE LOG SNIPPET</h6>", unsafe_allow_html=True)
            evidence_data = selected.get("evidence", [])
            if evidence_data:
                st.dataframe(pd.DataFrame(evidence_data), use_container_width=True, height=180)
        else:
            st.info("Select an alert from the matrix to inspect evidence details.")
