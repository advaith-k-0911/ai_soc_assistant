# Impeccable Quality & Design System Manifest 🛡️

**Project:** Enterprise AI SOC Assistant (SIEM Platform)  
**Status:** Initialized & Verified (`Exit Code 0`)  
**Design Standard:** Enterprise Security Operations Center (Microsoft Sentinel / CrowdStrike / Splunk / Elastic Security / VS Code)

---

## 🎨 1. Visual Style & Color Architecture

| Element | Token / Hex Code | Usage |
| :--- | :--- | :--- |
| **Page Background** | `#000000` | True Pitch Black canvas |
| **Surface Container** | `#0E1217` | Primary card panels and section containers |
| **Hover Surface** | `#212732` | Interactive element hover states |
| **Borders** | `#30363D` | Crisp 1px thin borders |
| **Primary Text** | `#E6EDF3` | Body and description text |
| **Muted Text** | `#8B949E` / `#6E7681` | Subtext, captions, and secondary labels |
| **Critical Severity** | `#F85149` | Critical security alert badges & indicators |
| **High Severity** | `#F0883E` | High risk threat badges |
| **Medium Severity** | `#D29922` | Medium risk threat badges |
| **Low Severity** | `#58A6FF` | Low risk / informational badges |

---

## ✒️ 2. Typography Hierarchy

- **Headings / Titles / Brand (`Space Grotesk`)**: Applied to all section titles, brand header (`ENTERPRISE SOC CONSOLE`), KPI card labels, buttons, and tab controls for an engineered display look.
- **Body & Descriptions (`Inter`)**: Applied to executive summaries, alert descriptions, technical reasoning, and creator profile copy for maximum legibility.
- **Technical Monospace (`JetBrains Mono`)**: Applied to IP addresses, timestamps, log output lines, hashes, code snippets, and MITRE technique IDs.

---

## 🧩 3. Navigation & UX Layout

- **Bottom Navigation Dock Bar**: Fixed horizontal dock anchored at the viewport bottom (`#bottom-nav-container`).
- **Inline Header Control Bar**: Expandable top bar for file ingestion (`CSV`, `LOG`, `TXT`, `JSON`) and synthetic demo dataset reset.
- **Modular Component Standard**:
  - `components/header.py`: Operational top header & status indicator.
  - `components/navigation.py`: Viewport bottom navigation dock.
  - `components/dashboard.py`: High-density SOC Overview & Plotly timeline.
  - `components/log_explorer.py`: Multi-column filterable log data grid.
  - `components/threat_matrix.py`: Correlated alerts & evidence log drawer.
  - `components/ai_console.py`: Hero AI Incident Analyst & Grounded RAG Chat.
  - `components/threat_intel.py`: IP Threat Reputation & MITRE ATT&CK Matrix.
  - `components/reports.py`: Executive PDF report compiler (`ReportLab`).
  - `components/settings.py`: Threshold tuning & API credentials.
  - `components/about.py`: Creator profile page (**Advaith K.**).

---

## ✅ 4. Verification & Readiness Summary

- **Syntax & Compilation**: Verified across all 17 Python codebase modules (`Exit Code 0`).
- **Backend Code Integrity**: 100% preservation of `SOCAnalyzer`, `SOCAIAssistant`, `parse_log_file`, and `generate_pdf_report`.
