"""
Enterprise SOC Visual Styling & Plotly Dark Theme Utilities
"""

import plotly.graph_objects as go


def apply_plotly_enterprise_theme(fig, height=320):
    """
    Standardize Plotly charts to match Microsoft Sentinel / Grafana dark enterprise styling.
    """
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(
            family="Inter, -apple-system, BlinkMacSystemFont, sans-serif",
            color="#8B949E",
            size=11
        ),
        margin=dict(l=15, r=15, t=35, b=15),
        height=height,
        legend=dict(
            font=dict(color="#C9D1D9", size=10),
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        ),
        xaxis=dict(
            gridcolor="#21262D",
            zerolinecolor="#21262D",
            tickfont=dict(color="#8B949E", size=10),
            showline=True,
            linecolor="#30363D"
        ),
        yaxis=dict(
            gridcolor="#21262D",
            zerolinecolor="#21262D",
            tickfont=dict(color="#8B949E", size=10),
            showline=True,
            linecolor="#30363D"
        ),
    )
    return fig


def get_severity_badge_html(severity: str) -> str:
    """Returns compact enterprise severity badge HTML."""
    sev_clean = str(severity).lower()
    if sev_clean == "critical":
        return '<span class="sev-badge sev-critical">CRITICAL</span>'
    elif sev_clean == "high":
        return '<span class="sev-badge sev-high">HIGH</span>'
    elif sev_clean == "medium":
        return '<span class="sev-badge sev-medium">MEDIUM</span>'
    else:
        return '<span class="sev-badge sev-low">LOW</span>'
