"""
Threat Intelligence & MITRE ATT&CK Framework Component
"""

import pandas as pd
import streamlit as st
from config import MITRE_ATTACK_DB
from utils import get_ip_location


def render_threat_intel(df: pd.DataFrame):
    """
    Renders Threat Intelligence IP lookup and MITRE ATT&CK framework registry.
    """
    st.markdown("""
        <div class="soc-panel-title" style="margin-bottom: 12px;">THREAT INTELLIGENCE & MITRE ATT&CK REGISTRY</div>
    """, unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["🔎 IP Reputation Query", "🧩 MITRE ATT&CK Registry"])

    with tab1:
        st.markdown("<h5 style='font-size:0.85rem; color:#8B949E; text-transform:uppercase;'>QUERY IP THREAT INTELLIGENCE DATABASE</h5>", unsafe_allow_html=True)
        
        lookup_ip = st.text_input("Enter IP Address:", "185.220.101.5")
        if st.button("Query Threat Intelligence"):
            loc = get_ip_location(lookup_ip)
            ip_logs = df[df["src_ip"] == lookup_ip] if not df.empty and "src_ip" in df.columns else pd.DataFrame()
            
            st.markdown(f"""
                <div class="soc-panel" style="margin-top: 14px;">
                    <div style="font-size: 0.9rem; font-weight: 700; color: #58A6FF; font-family:'JetBrains Mono'; margin-bottom: 6px;">
                        TARGET IP: {lookup_ip}
                    </div>
                    <div style="font-size: 0.8rem; color: #8B949E; margin-bottom: 4px;">
                        <b>Geolocation:</b> {loc['city']}, {loc['country']} | <b>ISP:</b> {loc['isp']}
                    </div>
                    <div style="font-size: 0.8rem; color: #8B949E; margin-bottom: 4px;">
                        <b>Correlated Log Records:</b> <span style="font-family:'JetBrains Mono'; color:#E6EDF3;">{len(ip_logs)} events</span>
                    </div>
                    <div style="font-size: 0.8rem; color: #F85149; font-weight: 600;">
                        CLASSIFICATION: HIGH RISK / SUSPICIOUS EXTERNAL HOST
                    </div>
                </div>
            """, unsafe_allow_html=True)
            
            if not ip_logs.empty:
                st.markdown("<h6 style='font-size:0.78rem; color:#8B949E; text-transform:uppercase;'>CORRELATED LOG REPOSITORY MATCHES</h6>", unsafe_allow_html=True)
                st.dataframe(ip_logs[["timestamp", "event_type", "username", "status", "message"]], use_container_width=True, height=250)

    with tab2:
        st.markdown("<h5 style='font-size:0.85rem; color:#8B949E; text-transform:uppercase;'>ENTERPRISE MITRE ATT&CK MATRIX REGISTRY</h5>", unsafe_allow_html=True)
        mitre_list = []
        for cat, data in MITRE_ATTACK_DB.items():
            mitre_list.append({
                "Threat Category": cat,
                "Technique ID": data["id"],
                "Technique Name": data["name"],
                "Tactic": data["tactic"],
                "Description": data["description"],
                "Mitigation Strategy": data["mitigation"]
            })
        st.dataframe(pd.DataFrame(mitre_list), use_container_width=True, height=450)
