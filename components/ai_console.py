"""
Hero AI Incident Investigation Console & Grounded RAG Chat Component
"""

import html
import streamlit as st
import pandas as pd
from components.styles import get_severity_badge_html
from state_helpers import ensure_investigation_report


def render_ai_console(ai_assistant, logs_df: pd.DataFrame):
    """
    Renders Hero AI Incident Investigation Console and Grounded Log Q&A Chat.
    """
    st.markdown("""
        <div class="soc-panel-title" style="margin-bottom: 12px;">HERO AI INCIDENT INVESTIGATION CONSOLE</div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([7, 5])

    with col1:
        st.markdown("<h5 style='font-size:0.85rem; color:#8B949E; text-transform:uppercase;'>AI INCIDENT REPORT OUTPUT</h5>", unsafe_allow_html=True)
        
        report = ensure_investigation_report(ai_assistant, logs_df)
        selected_alert = st.session_state.selected_alert

        if selected_alert and report:
            badge_html = get_severity_badge_html(selected_alert.get("severity", "High"))

            st.markdown(f"""
                <div class="soc-panel" style="border-color: #30363D;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 8px;">
                        <div style="font-size: 1rem; font-weight: 700; color: #58A6FF;">
                            AI INCIDENT REPORT &bull; {html.escape(str(selected_alert.get('alert_id', '')))}
                        </div>
                        {badge_html}
                    </div>
                    <div style="font-size: 0.76rem; color: #8B949E; margin-bottom: 14px; font-family: 'JetBrains Mono';">
                        Log-Grounded Correlation | Confidence Score: <b>{html.escape(str(report.get('confidence_score', 90)))}%</b>
                    </div>
                    <hr style="border-color:#21262D; margin-bottom: 12px;"/>

                    <div style="font-size:0.78rem; font-weight:600; color:#3FB950; text-transform:uppercase; margin-bottom:4px;">1. EXECUTIVE SUMMARY</div>
                    <div style="font-size:0.85rem; color:#E6EDF3; margin-bottom:14px; line-height:1.4;">
                        {html.escape(str(report.get('executive_summary', 'Analysis pending.')))}
                    </div>

                    <div style="font-size:0.78rem; font-weight:600; color:#58A6FF; text-transform:uppercase; margin-bottom:4px;">2. CORRELATED LOG EVIDENCE</div>
                    <pre style="background:#0D1117; border:1px solid #21262D; padding:10px; border-radius:4px; font-size:0.78rem; color:#8B949E; white-space:pre-wrap; margin-bottom:14px;">{html.escape(str(report.get('evidence', '')))}</pre>

                    <div style="font-size:0.78rem; font-weight:600; color:#D29922; text-transform:uppercase; margin-bottom:4px;">3. TECHNICAL REASONING & ROOT CAUSE</div>
                    <div style="font-size:0.85rem; color:#E6EDF3; margin-bottom:14px; line-height:1.4;">
                        {html.escape(str(report.get('reasoning', '')))}
                    </div>

                    <div style="font-size:0.78rem; font-weight:600; color:#BC8CFF; text-transform:uppercase; margin-bottom:4px;">4. MITRE ATT&CK ALIGNMENT</div>
                    <div style="font-size:0.85rem; color:#58A6FF; font-weight:600; margin-bottom:14px;">
                        {html.escape(str(report.get('mitre_mapping', '')))}
                    </div>

                    <div style="font-size:0.78rem; font-weight:600; color:#3FB950; text-transform:uppercase; margin-bottom:4px;">5. RECOMMENDED PLAYBOOK REMEDIATION</div>
                    <pre style="background:#0D1117; border:1px solid #21262D; padding:10px; border-radius:4px; font-size:0.78rem; color:#3FB950; white-space:pre-wrap; margin-bottom:14px;">{html.escape(str(report.get('recommendations', '')))}</pre>
                </div>
            """, unsafe_allow_html=True)

            act_col1, act_col2, act_col3 = st.columns(3)
            with act_col1:
                if st.button("💬 Ask RAG Chat", use_container_width=True):
                    st.toast("Use the RAG Chat on the right to inquire about specific log lines.", icon="💬")
            with act_col2:
                # Polish: Raw Markdown Ticket Snippet Export
                raw_summary = report.get('raw_report', report.get('executive_summary', ''))
                st.download_button(
                    label="📋 Download Ticket Snippet (.md)",
                    data=raw_summary,
                    file_name=f"Incident_Summary_{selected_alert['alert_id']}.md",
                    mime="text/markdown",
                    use_container_width=True
                )
            with act_col3:
                if st.button("✅ Mark Resolved", use_container_width=True):
                    st.toast(f"Incident {selected_alert['alert_id']} marked resolved in SIEM state.", icon="✅")
        else:
            st.info("Select an alert from the Threat Matrix to generate a grounded AI incident investigation report.")

    with col2:
        st.markdown("<h5 style='font-size:0.85rem; color:#8B949E; text-transform:uppercase;'>GROUNDED LOG Q&A ASSISTANT (RAG)</h5>", unsafe_allow_html=True)
        st.markdown("<div style='font-size:0.78rem; color:#8B949E; margin-bottom:8px;'>Natural language query over uploaded log context. Strictly grounded to prevent LLM hallucinations.</div>", unsafe_allow_html=True)

        chat_container = st.container(height=380)
        with chat_container:
            for message in st.session_state.chat_history:
                role = message["role"]
                content = message["content"]
                if role == "user":
                    st.markdown(f"""
                        <div style="background:#161B22; border:1px solid #30363D; border-radius:4px; padding:8px 12px; margin-bottom:8px;">
                            <div style="font-size:0.75rem; font-weight:600; color:#58A6FF; text-transform:uppercase;">USER ANALYST</div>
                            <div style="font-size:0.83rem; color:#E6EDF3;">{html.escape(str(content))}</div>
                        </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                        <div style="background:#0D1117; border:1px solid #3FB950; border-radius:4px; padding:8px 12px; margin-bottom:8px;">
                            <div style="font-size:0.75rem; font-weight:600; color:#3FB950; text-transform:uppercase;">AI SOC ENGINE</div>
                            <div style="font-size:0.83rem; color:#E6EDF3; line-height:1.4;">{html.escape(str(content))}</div>
                        </div>
                    """, unsafe_allow_html=True)

        st.markdown("<div style='font-size:0.72rem; color:#6E7681; margin-top:6px;'>Suggested Queries:</div>", unsafe_allow_html=True)
        q_cols = st.columns(3)
        prompt_text = ""
        if q_cols[0].button("Top Attackers"):
            prompt_text = "Who are the top attacker source IPs in the uploaded logs?"
        if q_cols[1].button("Failed Logins"):
            prompt_text = "Which accounts had excessive failed logins?"
        if q_cols[2].button("PowerShell Exec"):
            prompt_text = "Show details of any suspicious PowerShell commands executed."

        user_input = st.chat_input("Query security log context...")
        if prompt_text:
            user_input = prompt_text

        if user_input:
            st.session_state.chat_history.append({"role": "user", "content": user_input})
            with st.spinner("Retrieving grounded log evidence..."):
                response_text = st.write_stream(
                    ai_assistant.chat_with_logs_stream(
                        user_input, logs_df, st.session_state.chat_history
                    )
                )
                st.session_state.chat_history.append({"role": "assistant", "content": response_text})
            st.rerun()
