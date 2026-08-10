# Enterprise AI SOC Assistant 🛡️🤖

Production-quality **AI Security Operations Center (SOC) Assistant** built with **Python**, **Streamlit**, **Plotly**, **Groq API** (`llama-3.3-70b-versatile`), and **ReportLab**.

---

## 🌟 Features & UX Highlights

### 1. Clear Onboarding & Demo Mode State
- **First Launch**: Automatically loads synthetic sample security logs with a prominent, elegant **Demo Mode** info banner (`ℹ️ DEMO MODE`).
- **Live Analysis**: When a user uploads their own CSV, LOG, TXT, or JSON file, the system automatically transitions to **Live Analysis** (`🟢 LIVE ANALYSIS`) with a green confirmation banner.
- **Reload Demo**: Clicking "Load Synthetic Sample Logs" from the sidebar restores the Demo Mode banner.

### 2. Multi-Format Log Ingestion & Parser
- **Formats Supported**: CSV, Syslog (`.log` / `.txt`), and JSON / JSON Lines.
- **Normalizes** raw records into a unified schema: `timestamp`, `event_type`, `username`, `src_ip`, `dest_ip`, `port`, `status`, `message`, and `location`.

### 3. 9-Vector Rule-Based Detection Engine
Automatically correlates events and triggers structured alerts with severity levels (Critical, High, Medium, Low), confidence scores, and MITRE ATT&CK mappings:
1. **Brute-Force Attacks**
2. **Port Scanning**
3. **Multiple Failed Logins**
4. **Account Lockouts**
5. **Privilege Escalation**
6. **Suspicious PowerShell Activity**
7. **Excessive Failed Authentication**
8. **Impossible Travel Anomaly**
9. **Anomalous Off-Hours Logins**

### 4. Hero AI Incident Investigation Console
- Powered by **Groq API** (`llama-3.3-70b-versatile`) with strict log grounding to eliminate LLM hallucinations.
- Generates structured incident analysis reports covering Executive Summary, Evidence, Technical Reasoning, MITRE ATT&CK Alignment, and Remediation Playbooks.
- **Offline Fallback Engine**: Ensures 100% full functionality out-of-the-box even without an API key.

### 5. Grounded AI Log Q&A (RAG)
- Chat interface allowing natural language querying over uploaded logs with RAG context retrieval.

### 6. Interactive Dark Operations Dashboard
- Matte enterprise dark styling (`#0B0F14`, `#131A23`, `#1A2430`, `#22C55E`, `#38BDF8`).
- **Plotly Visualizations**: Incident Attack Timeline, Severity Distribution Donut, Global Threat Map, Top Attacker Source IPs.
- Live Correlated Threat Feed & Incident Details Drawer.

### 7. Automated PDF Executive Report Export
- Compiles executive overview, incident metadata, alert findings table, MITRE matrix, and remediation checklist into a styled PDF report (`ReportLab`).

---

## ⚡ Quick Start & Installation

```bash
cd C:\Users\Sudha\Documents\projects\ai_soc_assistant
pip install -r requirements.txt
streamlit run app.py
```

The app will open automatically in your browser at `http://localhost:8501`.
