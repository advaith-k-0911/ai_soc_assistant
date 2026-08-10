"""
Enterprise Bottom Navigation Dock Component (Replaces Left Sidebar)
"""

import streamlit as st

NAV_ITEMS = [
    {"id": "Overview", "label": "Overview", "icon": "📊"},
    {"id": "Log Explorer", "label": "Logs", "icon": "📋"},
    {"id": "Threat Matrix", "label": "Threat Matrix", "icon": "🚨"},
    {"id": "AI Investigation", "label": "AI Console", "icon": "🤖"},
    {"id": "Threat Intelligence", "label": "Threat Intel", "icon": "🎯"},
    {"id": "PDF Reports", "label": "PDF Reports", "icon": "📑"},
    {"id": "Settings", "label": "Settings", "icon": "⚙️"},
    {"id": "Built By", "label": "Built By", "icon": "👨‍💻"},
]


def render_bottom_navigation():
    """
    Renders engineered horizontal bottom navigation dock anchored at the bottom of the viewport.
    Returns the selected active view ID.
    """
    st.markdown("""
        <style>
            /* Hide Streamlit's default left sidebar completely */
            [data-testid="stSidebar"] {
                display: none !important;
            }
            
            /* Bottom Margin for main page container so content isn't overlapped by bottom bar */
            [data-testid="stMainBlockContainer"] {
                padding-bottom: 90px !important;
            }

            /* Bottom Nav Wrapper Styling */
            .bottom-nav-container {
                position: fixed;
                bottom: 0;
                left: 0;
                right: 0;
                z-index: 99999;
                background-color: #161B22 !important;
                border-top: 1px solid #30363D !important;
                padding: 6px 16px;
                box-shadow: 0 -6px 24px rgba(0, 0, 0, 0.7);
            }
        </style>
    """, unsafe_allow_html=True)

    options = [f"{item['icon']} {item['label']}" for item in NAV_ITEMS]
    index_map = {f"{item['icon']} {item['label']}": item['id'] for item in NAV_ITEMS}

    # Sticky Bottom Bar Container
    st.markdown('<div class="bottom-nav-container">', unsafe_allow_html=True)
    
    selected_option = st.radio(
        "Bottom Navigation Bar",
        options=options,
        index=0,
        horizontal=True,
        label_visibility="collapsed",
        key="bottom_nav_radio"
    )
    
    st.markdown('</div>', unsafe_allow_html=True)

    active_view = index_map.get(selected_option, "Overview")
    return active_view
