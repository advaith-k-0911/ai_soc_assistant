"""
Executive PDF Incident Report Generator UI Component
"""

import streamlit as st
import pandas as pd
from datetime import datetime
from report import generate_pdf_report


def render_reports(alerts: list, logs_df: pd.DataFrame):
    """
    Renders Executive PDF Incident Report Compiler and Download module.
    """
    st.markdown("""
        <div class="soc-panel-title" style="margin-bottom: 12px;">EXECUTIVE PDF INCIDENT REPORT EXPORT</div>
    """, unsafe_allow_html=True)

    report_data = st.session_state.investigation_report or {}

    st.markdown("""
        <div class="soc-panel">
            <div style="font-size: 0.9rem; font-weight: 600; color: #F0F6FC; margin-bottom: 4px;">
                Compile Official Executive Incident Report
            </div>
            <div style="font-size: 0.8rem; color: #8B949E; margin-bottom: 14px;">
                Generates a standardized ReportLab PDF compiling executive summary, correlated alert matrix, MITRE ATT&CK mappings, and recommended remediation playbooks.
            </div>
        </div>
    """, unsafe_allow_html=True)

    if st.button("⚙️ Compile PDF Report Document", type="primary"):
        with st.spinner("Compiling ReportLab PDF document..."):
            pdf_bytes = generate_pdf_report(
                incident_summary=report_data,
                alerts=alerts,
                logs_df=logs_df
            )
            st.session_state.pdf_bytes = pdf_bytes
            st.success("PDF Incident Report generated successfully!")

    if "pdf_bytes" in st.session_state:
        st.download_button(
            label="💾 Download Executive PDF Report",
            data=st.session_state.pdf_bytes,
            file_name=f"Executive_SOC_Incident_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
            mime="application/pdf"
        )
