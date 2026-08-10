"""
Configuration and Design System for AI SOC Assistant
Modern minimalist enterprise cybersecurity theme with deep black animated network background
"""

# Color Palette Definitions (Enterprise SIEM Palette - Pitch Black & Zinc)
COLORS = {
    "bg": "#000000",                 # True Pitch Black background
    "surface": "#12171E",            # Primary surface container
    "surface_secondary": "#181E27",  # Sub-container / table header
    "surface_hover": "#212732",      # Interactive hover state
    "border": "#30363D",             # Crisp 1px thin border
    "border_subtle": "#21262D",      # Subtle separator border
    "primary": "#58A6FF",            # Enterprise Accent Blue
    "accent": "#38BDF8",             # Cyan
    "text": "#E6EDF3",               # Primary text
    "text_secondary": "#8B949E",     # Secondary text
    "text_muted": "#6E7681",         # Muted caption text
    "critical": "#F85149",           # Red
    "high": "#F0883E",               # Orange
    "medium": "#D29922",             # Amber / Yellow
    "low": "#58A6FF",                # Sky Blue
    "info": "#BC8CFF",               # Purple
    "success": "#3FB950",            # Green
}

# Detection Threshold Rules
THRESHOLDS = {
    "brute_force_attempts": 5,      # Failures per IP/user within window
    "brute_force_window_min": 10,
    "port_scan_distinct_ports": 8,   # Ports hit by single IP
    "port_scan_window_min": 5,
    "multiple_failed_logins": 4,
    "excessive_failed_auth_surge": 15, # Network wide failure spike
    "impossible_travel_max_hours": 2, # Logins from different countries within 2 hrs
}

# Upload limits
UPLOAD_LIMITS = {
    "max_bytes": 50 * 1024 * 1024,  # 50 MB
    "max_rows": 100_000,
}

# Local business hours (24h clock) for off-hours login detection
BUSINESS_HOURS = {
    "start": 7,   # 07:00
    "end": 19,    # 19:00
}

# MITRE ATT&CK Framework Mapping Registry
MITRE_ATTACK_DB = {
    "Brute Force": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown.",
        "mitigation": "Enforce strong password policies, account lockouts after 5 failed attempts, and multi-factor authentication (MFA)."
    },
    "Port Scanning": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts to identify vulnerable targets.",
        "mitigation": "Configure stateful firewalls, disable unused ports/services, and deploy Network Intrusion Detection Systems (NIDS)."
    },
    "Multiple Failed Logins": {
        "id": "T1110.001",
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversaries may iterate through common passwords against targeted accounts to gain unauthorized access.",
        "mitigation": "Implement rate limiting on login endpoints and mandate MFA."
    },
    "Account Lockout": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence",
        "description": "Repeated failed authentication triggering domain or local account lockout policies.",
        "mitigation": "Investigate root cause host, review compromised credentials, and enforce conditional access policies."
    },
    "Privilege Escalation": {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities or misconfigurations to elevate user privileges to root/system.",
        "mitigation": "Apply least privilege principles, restrict sudo access, and patch vulnerable operating systems and kernel software."
    },
    "Suspicious PowerShell": {
        "id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may execute malicious PowerShell scripts, base64 encoded payloads, or bypass execution policies.",
        "mitigation": "Enable PowerShell Constrained Language Mode, script block logging (Event ID 4104), and AMSI protection."
    },
    "Excessive Failed Auth": {
        "id": "T1110.003",
        "name": "Password Spraying",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt a single common password against many accounts to avoid lockout thresholds.",
        "mitigation": "Deploy behavioral anomaly detection, IP reputation filtering, and passwordless authentication."
    },
    "Impossible Travel": {
        "id": "T1078.004",
        "name": "Cloud Accounts / Anomalous Location Access",
        "tactic": "Initial Access",
        "description": "Logins detected from geographically disparate locations within a time frame physically impossible to travel.",
        "mitigation": "Require identity re-authentication (MFA prompt), restrict login locations via Geofencing, and revoke compromised active sessions."
    },
    "Anomalous Login Behavior": {
        "id": "T1078.002",
        "name": "Domain Accounts",
        "tactic": "Defense Evasion",
        "description": "Authentication originating during non-business hours, unusual user-agents, or unassigned IP subnets.",
        "mitigation": "Establish User and Entity Behavior Analytics (UEBA) baseline triggers and conditional access."
    }
}

# High-Density Enterprise Dark CSS (Pitch Black Theme with Space Grotesk Headings & Inter Body)
CUSTOM_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700;800&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* Global Overrides - Pitch Black Background */
    html, body, [data-testid="stAppViewContainer"], [data-testid="stHeader"], [data-testid="stMainBlockContainer"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        background-color: #000000 !important;
        color: #E6EDF3 !important;
    }

    [data-testid="stHeader"] {
        background-color: #000000 !important;
        border-bottom: 1px solid #21262D !important;
    }

    [data-testid="stMainBlockContainer"] {
        padding-top: 1.2rem !important;
        padding-bottom: 2rem !important;
        max-width: 98% !important;
    }

    #MainMenu, footer { visibility: hidden; }

    /* Heading Typography - Space Grotesk */
    h1, h2, h3, h4, h5, h6, .soc-panel-title, .kpi-card-label {
        font-family: 'Space Grotesk', -apple-system, BlinkMacSystemFont, sans-serif !important;
        letter-spacing: -0.01em !important;
    }

    /* Body & Description Typography - Inter */
    p, li, span, div, label {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* Technical Monospace Elements */
    code, pre, .mono-font, [data-testid="stTable"] td {
        font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
    }

    /* Enterprise Header Bar */
    .soc-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: #0E1217;
        border: 1px solid #30363D;
        border-radius: 6px;
        padding: 12px 22px;
        margin-bottom: 18px;
    }

    .soc-brand {
        display: flex;
        align-items: center;
        gap: 14px;
        font-family: 'Space Grotesk', sans-serif !important;
        font-weight: 800 !important;
        font-size: 1.45rem !important;
        letter-spacing: -0.02em !important;
        color: #FFFFFF !important;
    }

    .soc-brand-tag {
        font-family: 'Space Grotesk', sans-serif !important;
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        background: #21262D;
        color: #58A6FF;
        border: 1px solid #30363D;
        padding: 3px 10px;
        border-radius: 4px;
    }

    .soc-status-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-family: 'Space Grotesk', sans-serif;
        font-size: 0.75rem;
        font-weight: 700;
        padding: 4px 12px;
        border-radius: 4px;
        letter-spacing: 0.4px;
        text-transform: uppercase;
    }
    .soc-status-live {
        background: rgba(63, 185, 80, 0.12);
        color: #3FB950;
        border: 1px solid rgba(63, 185, 80, 0.3);
    }
    .soc-status-demo {
        background: #DC2626 !important;
        color: #FFFFFF !important;
        border: 1px solid #EF4444 !important;
        font-weight: 800 !important;
    }

    /* Compact KPI Card Widgets */
    .kpi-card {
        background: #0E1217;
        border: 1px solid #30363D;
        border-radius: 6px;
        padding: 14px 18px;
        margin-bottom: 12px;
    }
    .kpi-card-label {
        font-family: 'Space Grotesk', sans-serif !important;
        font-size: 0.75rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: #8B949E;
        margin-bottom: 6px;
    }
    .kpi-card-value {
        font-family: 'Space Grotesk', sans-serif !important;
        font-size: 1.75rem;
        font-weight: 700;
        color: #FFFFFF;
        line-height: 1.2;
    }
    .kpi-card-subtext {
        font-family: 'Inter', sans-serif;
        font-size: 0.73rem;
        color: #6E7681;
        margin-top: 4px;
    }

    /* Severity Badges */
    .sev-badge {
        display: inline-block;
        font-family: 'Space Grotesk', sans-serif;
        font-size: 0.7rem;
        font-weight: 700;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        padding: 2px 8px;
        border-radius: 4px;
        line-height: 1.2;
    }
    .sev-critical {
        background: rgba(248, 81, 73, 0.18);
        color: #F85149;
        border: 1px solid rgba(248, 81, 73, 0.45);
    }
    .sev-high {
        background: rgba(240, 136, 62, 0.18);
        color: #F0883E;
        border: 1px solid rgba(240, 136, 62, 0.45);
    }
    .sev-medium {
        background: rgba(210, 153, 34, 0.18);
        color: #D29922;
        border: 1px solid rgba(210, 153, 34, 0.45);
    }
    .sev-low {
        background: rgba(88, 166, 255, 0.18);
        color: #58A6FF;
        border: 1px solid rgba(88, 166, 255, 0.45);
    }

    /* Enterprise Panel Containers */
    .soc-panel {
        background: #0E1217;
        border: 1px solid #30363D;
        border-radius: 6px;
        padding: 18px;
        margin-bottom: 16px;
    }
    .soc-panel-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        border-bottom: 1px solid #21262D;
        padding-bottom: 10px;
        margin-bottom: 14px;
    }
    .soc-panel-title {
        font-family: 'Space Grotesk', sans-serif !important;
        font-size: 0.92rem;
        font-weight: 700;
        color: #FFFFFF;
        text-transform: uppercase;
        letter-spacing: 0.4px;
    }

    /* Threat Stream Feed */
    .threat-item {
        background: #05070A;
        border: 1px solid #21262D;
        border-left: 3px solid #58A6FF;
        border-radius: 4px;
        padding: 12px 16px;
        margin-bottom: 8px;
    }
    .threat-item.critical { border-left-color: #F85149; }
    .threat-item.high { border-left-color: #F0883E; }
    .threat-item.medium { border-left-color: #D29922; }
    .threat-item.low { border-left-color: #58A6FF; }

    /* MITRE ATT&CK Matrix Grid */
    .mitre-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
        gap: 8px;
        margin-top: 10px;
    }
    .mitre-cell {
        background: #05070A;
        border: 1px solid #21262D;
        border-radius: 4px;
        padding: 8px;
        font-size: 0.72rem;
    }
    .mitre-cell-active {
        border-color: #F85149;
        background: rgba(248, 81, 73, 0.08);
    }
    .mitre-cell-title {
        font-family: 'Space Grotesk', sans-serif;
        font-weight: 700;
        color: #C9D1D9;
        margin-bottom: 2px;
    }
    .mitre-cell-id {
        font-family: 'JetBrains Mono', monospace;
        color: #8B949E;
    }

    /* Bottom Navigation Container Bar */
    .bottom-nav-container {
        position: fixed;
        bottom: 0;
        left: 0;
        right: 0;
        z-index: 99999;
        background-color: #0E1217 !important;
        border-top: 1px solid #30363D !important;
        padding: 8px 16px;
        box-shadow: 0 -8px 30px rgba(0, 0, 0, 0.9);
    }

    /* Buttons Override */
    .stButton > button {
        font-family: 'Space Grotesk', sans-serif !important;
        background-color: #21262D !important;
        color: #C9D1D9 !important;
        border: 1px solid #30363D !important;
        border-radius: 6px !important;
        font-size: 0.84rem !important;
        font-weight: 600 !important;
        padding: 7px 14px !important;
        transition: background-color 0.15s ease, border-color 0.15s ease !important;
    }
    .stButton > button:hover {
        background-color: #30363D !important;
        border-color: #8B949E !important;
        color: #FFFFFF !important;
    }

    /* Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {
        background-color: #0E1217 !important;
        border: 1px solid #30363D !important;
        border-radius: 6px !important;
        padding: 4px !important;
        gap: 4px !important;
    }
    .stTabs [data-baseweb="tab"] {
        font-family: 'Space Grotesk', sans-serif !important;
        height: 36px !important;
        border-radius: 4px !important;
        color: #8B949E !important;
        font-size: 0.84rem !important;
        font-weight: 600 !important;
    }
    .stTabs [aria-selected="true"] {
        background-color: #21262D !important;
        color: #FFFFFF !important;
    }

    /* Custom Scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    ::-webkit-scrollbar-track {
        background: #000000;
    }
    ::-webkit-scrollbar-thumb {
        background: #21262D;
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #30363D;
    }
</style>
"""

# Cleanup script
NETWORK_CANVAS_HTML = """
<img src="data:image/svg+xml," onerror="
(function() {
    var targetDoc = window.parent ? window.parent.document : window.document;
    var canvas = targetDoc.getElementById('bg-soc-network');
    if (canvas) canvas.remove();
})()
" style="display:none;" />
"""


