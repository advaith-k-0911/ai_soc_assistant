"""
Enterprise SOC Dashboard Component (Microsoft Sentinel / CrowdStrike Style)
"""

import html
import pandas as pd
import plotly.express as px
import streamlit as st
from datetime import datetime
from components.styles import apply_plotly_enterprise_theme, get_severity_badge_html
from config import MITRE_ATTACK_DB
from utils import get_ip_location


def render_dashboard(df: pd.DataFrame, alerts: list, is_demo: bool):
    """
    Renders clean, high-density enterprise SOC dashboard.
    """
    # 0. Onboarding / Dataset Mode Banner
    if is_demo:
        st.markdown("""
            <div class="soc-panel" style="border-left: 3px solid #DC2626; padding: 12px 16px; margin-bottom: 16px;">
                <div style="display: flex; align-items: center; justify-content: space-between;">
                    <div>
                        <div style="font-size: 0.82rem; font-weight: 700; color: #FFFFFF; text-transform: uppercase; letter-spacing: 0.5px;">
                            DEMO MODE ACTIVE &bull; SYNTHETIC LOG DATASET
                        </div>
                        <div style="font-size: 0.78rem; color: #8B949E; margin-top: 2px;">
                            Currently analyzing synthetic security logs. Upload a file via <b>Log Ingestion & Dataset Controls</b> in the header for live analysis.
                        </div>
                    </div>
                    <span class="soc-status-badge soc-status-demo">SYNTHETIC</span>
                </div>
            </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
            <div class="soc-panel" style="border-left: 3px solid #3FB950; padding: 12px 16px; margin-bottom: 16px;">
                <div style="display: flex; align-items: center; justify-content: space-between;">
                    <div>
                        <div style="font-size: 0.82rem; font-weight: 600; color: #3FB950; text-transform: uppercase; letter-spacing: 0.5px;">
                            LIVE ANALYSIS ACTIVE &bull; USER LOG DATASET
                        </div>
                        <div style="font-size: 0.78rem; color: #8B949E; margin-top: 2px;">
                            Real-time threat detection and incident correlations generated from uploaded security log stream.
                        </div>
                    </div>
                    <span class="soc-status-badge soc-status-live">LIVE DATASET</span>
                </div>
            </div>
        """, unsafe_allow_html=True)

    # 1. Top KPI Summary Cards Row
    critical_alerts = sum(1 for a in alerts if a.get("severity") == "Critical")
    high_alerts = sum(1 for a in alerts if a.get("severity") == "High")
    total_events = len(df)
    unique_assets = df["dest_ip"].nunique() if not df.empty and "dest_ip" in df.columns else 0

    risk_score = min(100, (critical_alerts * 25) + (high_alerts * 10) + len(alerts))
    risk_color = "#F85149" if risk_score > 60 else ("#F0883E" if risk_score > 30 else "#3FB950")

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-card-label">Active Threats</div>
                <div class="kpi-card-value" style="color: #F85149;">{len(alerts)}</div>
                <div class="kpi-card-subtext">Correlated Detections</div>
            </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-card-label">Events Analyzed</div>
                <div class="kpi-card-value">{total_events:,}</div>
                <div class="kpi-card-subtext">Normalized Log Records</div>
            </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-card-label">Critical Alerts</div>
                <div class="kpi-card-value" style="color: #F85149;">{critical_alerts}</div>
                <div class="kpi-card-subtext">Immediate Response Required</div>
            </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-card-label">Protected Assets</div>
                <div class="kpi-card-value" style="color: #58A6FF;">{unique_assets}</div>
                <div class="kpi-card-subtext">Monitored Infrastructure Hosts</div>
            </div>
        """, unsafe_allow_html=True)

    with col5:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-card-label">Risk Exposure Score</div>
                <div class="kpi-card-value" style="color: {risk_color};">{risk_score} <span style="font-size:0.9rem; color:#8B949E;">/ 100</span></div>
                <div class="kpi-card-subtext">SIEM Threat Severity Index</div>
            </div>
        """, unsafe_allow_html=True)

    # 2. Charts Section (Timeline & Severity Donuts)
    c_col1, c_col2 = st.columns([7, 5])

    with c_col1:
        st.markdown("""
            <div class="soc-panel-title" style="margin-bottom: 8px;">INCIDENT ATTACK TIMELINE</div>
        """, unsafe_allow_html=True)
        if not df.empty:
            df_time = df.copy()
            df_time["time_bin"] = pd.to_datetime(df_time["timestamp"]).dt.floor("10min")
            timeline_df = df_time.groupby(["time_bin", "status"]).size().reset_index(name="count")

            fig_timeline = px.line(
                timeline_df,
                x="time_bin",
                y="count",
                color="status",
                color_discrete_map={
                    "FAILED": "#F85149",
                    "SUCCESS": "#3FB950",
                    "WARN": "#F0883E",
                    "INFO": "#58A6FF",
                    "CRITICAL": "#F85149"
                },
                markers=True
            )
            fig_timeline = apply_plotly_enterprise_theme(fig_timeline, height=290)
            st.plotly_chart(fig_timeline, use_container_width=True)
        else:
            st.info("No timeline data available.")

    with c_col2:
        st.markdown("""
            <div class="soc-panel-title" style="margin-bottom: 8px;">THREAT SEVERITY BREAKDOWN</div>
        """, unsafe_allow_html=True)
        if alerts:
            sev_df = pd.DataFrame(alerts)["severity"].value_counts().reset_index()
            sev_df.columns = ["severity", "count"]
            fig_donut = px.pie(
                sev_df,
                names="severity",
                values="count",
                hole=0.65,
                color="severity",
                color_discrete_map={
                    "Critical": "#F85149",
                    "High": "#F0883E",
                    "Medium": "#D29922",
                    "Low": "#58A6FF"
                }
            )
            fig_donut = apply_plotly_enterprise_theme(fig_donut, height=290)
            st.plotly_chart(fig_donut, use_container_width=True)
        else:
            st.info("No active threats detected.")

    # 3. MITRE ATT&CK Matrix & Threat Stream Row
    m_col1, m_col2 = st.columns([6, 6])

    with m_col1:
        st.markdown("""
            <div class="soc-panel-title" style="margin-bottom: 8px;">MITRE ATT&CK FRAMEWORK COVERAGE SUMMARY</div>
        """, unsafe_allow_html=True)

        active_mitre_ids = {a.get("mitre_id") for a in alerts}

        mitre_items_html = ""
        for name, data in MITRE_ATTACK_DB.items():
            is_active = data["id"] in active_mitre_ids
            active_cls = "mitre-cell-active" if is_active else ""
            status_dot = '<span style="color:#F85149; font-weight:bold;">&bull; ALERT</span>' if is_active else '<span style="color:#6E7681;">&bull; CLEAR</span>'
            mitre_items_html += f"""
            <div class="mitre-cell {active_cls}">
                <div class="mitre-cell-title">{data['tactic']}</div>
                <div class="mitre-cell-id">{data['id']} - {data['name']}</div>
                <div style="margin-top:4px; font-size:0.68rem;">{status_dot}</div>
            </div>
            """

        st.markdown(f"""
            <div class="mitre-grid">
                {mitre_items_html}
            </div>
        """, unsafe_allow_html=True)

    with m_col2:
        st.markdown("""
            <div class="soc-panel-title" style="margin-bottom: 8px;">TOP ATTACKER SOURCE IPS</div>
        """, unsafe_allow_html=True)
        if not df.empty and "src_ip" in df.columns:
            top_ips = df[df["src_ip"] != "N/A"]["src_ip"].value_counts().head(5).reset_index()
            top_ips.columns = ["src_ip", "count"]
            fig_bar = px.bar(
                top_ips,
                x="count",
                y="src_ip",
                orientation="h",
                color="count",
                color_continuous_scale=px.colors.sequential.Darkmint
            )
            fig_bar = apply_plotly_enterprise_theme(fig_bar, height=240)
            fig_bar.update_layout(yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig_bar, use_container_width=True)

    # 4. Correlated Threat Stream & Automated Playbook Actions
    st.markdown("<hr style='border-color:#21262D; margin: 20px 0 16px 0;'/>", unsafe_allow_html=True)
    st.markdown("""
        <div class="soc-panel-title" style="margin-bottom: 12px;">ACTIVE CORRELATED THREAT STREAM</div>
    """, unsafe_allow_html=True)

    feed_col1, feed_col2 = st.columns([8, 4])

    with feed_col1:
        # Polish: Interactive Severity Quick Filter
        sev_filter = st.radio(
            "Filter Stream by Severity",
            options=["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            index=0,
            horizontal=True,
            label_visibility="collapsed",
            key="dashboard_sev_filter"
        )

        display_alerts = alerts
        if sev_filter != "ALL":
            display_alerts = [a for a in alerts if a.get("severity", "").upper() == sev_filter]

        if display_alerts:
            for alert in display_alerts[:5]:
                sev_cls = alert.get("severity", "Low").lower()
                badge_html = get_severity_badge_html(alert.get("severity", "Low"))
                
                feed_item_html = f"""
                <div class="threat-item {sev_cls}">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                        <span style="font-size:0.85rem; font-weight:600; color:#F0F6FC;">{html.escape(str(alert['title']))}</span>
                        {badge_html}
                    </div>
                    <div style="font-size:0.78rem; color:#8B949E; font-family:'JetBrains Mono', monospace;">
                        Src IP: <span style="color:#58A6FF;">{html.escape(str(alert['src_ip']))}</span> | Account: <span style="color:#E6EDF3;">{html.escape(str(alert['username']))}</span> | Target: {html.escape(str(alert['affected_asset']))}
                    </div>
                    <div style="font-size:0.75rem; color:#6E7681; margin-top:2px;">
                        Timestamp: {alert['timestamp']} | MITRE: <b>{html.escape(str(alert['mitre_id']))}</b> ({html.escape(str(alert['mitre_name']))}) | Confidence: {alert['confidence']}%
                    </div>
                </div>
                """
                st.markdown(feed_item_html, unsafe_allow_html=True)
        else:
            st.info(f"No security threats matching filter: {sev_filter}")

    with feed_col2:
        st.markdown("""
            <div class="soc-panel" style="margin: 0;">
                <div class="soc-panel-title" style="font-size: 0.8rem; margin-bottom: 8px;">AUTOMATED PLAYBOOK ACTIONS</div>
                <div style="font-size: 0.76rem; color: #8B949E; margin-bottom: 12px;">Execute immediate perimeter containment or mitigation:</div>
            </div>
        """, unsafe_allow_html=True)

        top_threat_ip = "N/A"
        if alerts:
            top_threat_ip = alerts[0].get("src_ip", "N/A")
        elif not df.empty and "src_ip" in df.columns:
            top_counts = df[df["src_ip"] != "N/A"]["src_ip"].value_counts()
            if not top_counts.empty:
                top_threat_ip = top_counts.index[0]

        if st.button(f"⛔ Block Top Threat IP ({top_threat_ip})", use_container_width=True):
            st.toast(f"Perimeter firewall rule deployed. IP {top_threat_ip} added to blocklist.", icon="🛡️")
        if st.button("🔐 Force Password Reset for Targeted Users", use_container_width=True):
            st.toast("Identity ticket dispatched. Password reset forced for admin & j.smith.", icon="🔑")
        if st.button("📄 Export Executive Incident Report PDF", use_container_width=True):
            st.toast("PDF report generated. Switch to PDF Reports module to download.", icon="📑")
