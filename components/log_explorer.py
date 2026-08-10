"""
Enterprise Log Explorer & Data Grid Component
"""

import pandas as pd
import streamlit as st
from datetime import datetime


def render_log_explorer(df: pd.DataFrame):
    """
    Renders high-density SIEM log explorer data grid with search, filtering, and export.
    """
    st.markdown("""
        <div class="soc-panel-title" style="margin-bottom: 12px;">LOG NORMALIZATION & ENTERPRISE DATA GRID</div>
    """, unsafe_allow_html=True)

    if df.empty:
        st.warning("No normalized logs loaded.")
        return

    # Filter Controls Bar
    col1, col2, col3 = st.columns([4, 4, 4])

    with col1:
        search_query = st.text_input("🔍 Search Logs (IP, Username, Keyword):", "", placeholder="e.g. 185.220.101.5 or j.smith")

    with col2:
        available_statuses = list(df["status"].unique()) if "status" in df.columns else []
        status_filter = st.multiselect("Status Filter:", options=available_statuses, default=available_statuses)

    with col3:
        available_events = list(df["event_type"].unique()) if "event_type" in df.columns else []
        event_filter = st.multiselect("Event Type Filter:", options=available_events, default=available_events)

    # Filter dataframe
    filtered_df = df.copy()

    if status_filter and "status" in filtered_df.columns:
        filtered_df = filtered_df[filtered_df["status"].isin(status_filter)]

    if event_filter and "event_type" in filtered_df.columns:
        filtered_df = filtered_df[filtered_df["event_type"].isin(event_filter)]

    if search_query:
        q = search_query.lower()
        mask = pd.Series(False, index=filtered_df.index)
        for col in ["src_ip", "dest_ip", "username", "message", "event_type", "status"]:
            if col in filtered_df.columns:
                mask |= filtered_df[col].astype(str).str.lower().str.contains(q, na=False)
        filtered_df = filtered_df[mask]

    # Counter summary bar
    st.markdown(f"""
        <div style="display: flex; justify-content: space-between; align-items: center; margin: 10px 0;">
            <div style="font-size: 0.8rem; color: #8B949E;">
                Displaying <b style="color: #58A6FF;">{len(filtered_df):,}</b> of <b style="color: #E6EDF3;">{len(df):,}</b> normalized log records
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Data Table View
    st.dataframe(
        filtered_df,
        use_container_width=True,
        height=450
    )

    # CSV Download Button
    csv_bytes = filtered_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📥 Export Filtered Logs CSV",
        data=csv_bytes,
        file_name=f"soc_normalized_logs_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
        mime="text/csv"
    )
