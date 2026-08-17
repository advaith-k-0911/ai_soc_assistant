"""
Correlated Threat Matrix & Incident Drawer Component
"""

import pandas as pd
import streamlit as st
import html
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

            safe_alert_id = html.escape(str(alert.get('alert_id', '')))
            safe_title = html.escape(str(alert.get('title', '')))
            safe_src_ip = html.escape(str(alert.get('src_ip', '')))
            safe_username = html.escape(str(alert.get('username', '')))
            safe_asset = html.escape(str(alert.get('affected_asset', '')))
            safe_mitre_id = html.escape(str(alert.get('mitre_id', '')))
            safe_mitre_name = html.escape(str(alert.get('mitre_name', '')))
            safe_tactic = html.escape(str(alert.get('tactic', '')))
            safe_desc = html.escape(str(alert.get('description', '')))

            with st.expander(f"[{safe_alert_id}] {safe_title} — ({sev.upper()})", expanded=(idx == 0)):
                st.markdown(f"""
                    <div style="font-size: 0.82rem; margin-bottom: 8px;">
                        <b>Severity:</b> {badge_html} | <b>Confidence:</b> <span style="color:#58A6FF; font-family:'JetBrains Mono';">{alert['confidence']}%</span>
                    </div>
                    <div style="font-size: 0.8rem; color: #8B949E; font-family: 'JetBrains Mono', monospace; margin-bottom: 8px;">
                        Source IP: <span style="color:#58A6FF;">{safe_src_ip}</span> | User: <span>{safe_username}</span> | Asset: {safe_asset}
                    </div>
                    <div style="font-size: 0.8rem; color: #C9D1D9; margin-bottom: 8px;">
                        <b>MITRE ATT&CK:</b> {safe_mitre_id} - <i>{safe_mitre_name}</i> ({safe_tactic})
                    </div>
                    <div style="font-size: 0.78rem; color: #8B949E; margin-bottom: 12px;">
                        {safe_desc}
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

            safe_sel_title = html.escape(str(selected.get('title', '')))
            safe_sel_id = html.escape(str(selected.get('alert_id', '')))
            safe_sel_src_ip = html.escape(str(selected.get('src_ip', '')))
            safe_sel_username = html.escape(str(selected.get('username', '')))
            safe_sel_asset = html.escape(str(selected.get('affected_asset', '')))
            safe_sel_mitre_id = html.escape(str(selected.get('mitre_id', '')))
            safe_sel_mitre_name = html.escape(str(selected.get('mitre_name', '')))
            safe_sel_rec = html.escape(str(selected.get('recommendation', '')))

            st.markdown(f"""
                <div class="soc-panel">
                    <div style="font-size: 0.95rem; font-weight: 700; color: #F0F6FC; margin-bottom: 6px;">
                        {safe_sel_title}
                    </div>
                    <div style="margin-bottom: 12px;">
                        {badge_html}
                        <span style="font-size: 0.75rem; color: #8B949E; margin-left: 8px; font-family:'JetBrains Mono';">
                            ID: {safe_sel_id} | Confidence: {selected['confidence']}%
                        </span>
                    </div>
                    <div style="font-size: 0.8rem; color: #8B949E; margin-bottom: 4px;">
                        <b>Source IP:</b> <span style="font-family:'JetBrains Mono'; color:#58A6FF;">{safe_sel_src_ip}</span>
                    </div>
                    <div style="font-size: 0.8rem; color: #8B949E; margin-bottom: 4px;">
                        <b>Target Account:</b> {safe_sel_username}
                    </div>
                    <div style="font-size: 0.8rem; color: #8B949E; margin-bottom: 4px;">
                        <b>Destination Asset:</b> {safe_sel_asset}
                    </div>
                    <div style="font-size: 0.8rem; color: #8B949E; margin-bottom: 12px;">
                        <b>MITRE Technique:</b> {safe_sel_mitre_id} ({safe_sel_mitre_name})
                    </div>
                    <hr style="border-color:#21262D; margin: 10px 0;"/>
                    <div style="font-size: 0.78rem; font-weight: 600; color: #3FB950; text-transform: uppercase; margin-bottom: 4px;">RECOMMENDED MITIGATION</div>
                    <div style="font-size: 0.8rem; color: #C9D1D9;">
                        {safe_sel_rec}
                    </div>
                </div>
            """, unsafe_allow_html=True)

            st.markdown("<h6 style='font-size:0.78rem; color:#8B949E; text-transform:uppercase;'>EVIDENCE LOG SNIPPET</h6>", unsafe_allow_html=True)
            evidence_data = selected.get("evidence", [])
            if evidence_data:
                st.dataframe(pd.DataFrame(evidence_data), use_container_width=True, height=180)
        else:
            st.info("Select an alert from the matrix to inspect evidence details.")
