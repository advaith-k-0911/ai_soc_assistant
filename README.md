# Enterprise AI SOC Assistant

> An AI-powered Security Operations Center (SOC) platform for analyzing security logs, detecting threats, and generating incident reports.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-Web_App-red?style=for-the-badge&logo=streamlit)
![Groq](https://img.shields.io/badge/Groq-LLM-green?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-success?style=for-the-badge)

---

## Overview

Enterprise AI SOC Assistant is a modern Security Operations Center (SOC) platform that combines rule-based threat detection with AI-assisted incident investigation.

It enables security analysts to upload log files, detect suspicious activities, visualize attacks, investigate incidents using AI, and generate professional PDF reports.

The application is built using **Python**, **Streamlit**, **Plotly**, **Groq Llama 3.3**, and **ReportLab**.

---

## Features

### Multi-format Log Analysis

Supports:

- CSV
- JSON
- JSONL
- TXT
- LOG (Syslog)

Logs are automatically normalized into a common format for analysis.

---

### Threat Detection Engine

Detects multiple attack vectors including:

- Brute Force Attacks
- Port Scanning
- Multiple Failed Logins
- Account Lockouts
- Privilege Escalation
- Suspicious PowerShell Activity
- Excessive Failed Authentication
- Impossible Travel
- Off-Hours Logins

Each alert includes:

- Severity
- Confidence Score
- MITRE ATT&CK Mapping
- Evidence
- Recommended Remediation

---

### AI Incident Investigation

Powered by **Groq Llama 3.3 70B**

The AI analyst can:

- Explain detected attacks
- Perform evidence-based investigations
- Map attacks to MITRE ATT&CK
- Recommend remediation steps

If no API key is available, the application automatically switches to an offline heuristic engine.

---

### AI Log Chat (RAG)

Ask questions such as:

- Which IP generated the most attacks?
- Show failed login attempts.
- What happened before the brute force attack?
- Which users were targeted?

The assistant answers only using uploaded log data.

---

### Interactive SOC Dashboard

Includes:

- Security KPIs
- Attack Timeline
- Severity Distribution
- Threat Map
- Top Attacking IPs
- Alert Explorer

---

### Executive PDF Reports

Generate professional SOC reports containing:

- Executive Summary
- Alert Details
- MITRE ATT&CK Mapping
- Investigation Findings
- Recommended Actions

---

## Screenshots

> Replace these placeholders with your screenshots.

| Dashboard | AI Investigation |
|-----------|------------------|
| ![](assets/dashboard.png) | ![](assets/ai.png) |

---

## Tech Stack

### Frontend

- Streamlit
- Plotly

### Backend

- Python
- Pandas
- NumPy

### AI

- Groq API
- Llama 3.3 70B

### Reporting

- ReportLab

### Framework

- MITRE ATT&CK

---

## Installation

Clone the repository:

```bash
git clone https://github.com/advaith-k-0911/ai_soc_assistant.git
cd ai_soc_assistant
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create a `.env` file:

```env
GROQ_API_KEY=your_api_key_here
```

Run the application:

```bash
streamlit run app.py
```

---

## Project Structure

```text
ai_soc_assistant/
│
├── app.py
├── analyzer.py
├── ai.py
├── report.py
├── utils.py
├── config.py
├── state_helpers.py
│
├── components/
│   ├── dashboard.py
│   ├── ai_console.py
│   ├── reports.py
│   ├── settings.py
│   └── ...
│
├── sample_logs/
├── assets/
└── requirements.txt
```

---

## Future Improvements

- Threat Intelligence API Integration
- VirusTotal Integration
- Sigma Rule Support
- YARA Rule Support
- IOC Enrichment
- SIEM Connectors
- Dark Mode Themes
- Multi-user Authentication
- Docker Deployment

---

## Author

**Advaith K**

Cybersecurity • AI • Machine Learning

Building intelligent security solutions using AI.

**GitHub**  
https://github.com/advaith-k-0911

**LinkedIn**  
(Add your LinkedIn profile)

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

Made with ☕, Python, and sleep deprivation by **Advaith K** <3
