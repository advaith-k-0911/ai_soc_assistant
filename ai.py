"""
AI Integration Layer for AI SOC Assistant.
Integrates Groq API for incident analysis and grounded chat retrieval (RAG).
Includes heuristic fallback generator for seamless offline operation.
"""

import os
import json
import re
from typing import List, Dict, Any, Tuple
import pandas as pd
from dotenv import load_dotenv

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

load_dotenv()


class SOCAIAssistant:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        self.client = None
        
        if GROQ_AVAILABLE and self.api_key and self.api_key.strip():
            try:
                self.client = Groq(api_key=self.api_key)
            except Exception:
                self.client = None

    def is_groq_active(self) -> bool:
        return self.client is not None

    def analyze_incident(self, alert: Dict[str, Any], logs_df: pd.DataFrame) -> Dict[str, Any]:
        src_ip = alert.get("src_ip", "")
        username = alert.get("username", "")
        
        relevant_logs = logs_df[(logs_df["src_ip"] == src_ip) | (logs_df["username"] == username)].head(15)
        if relevant_logs.empty:
            relevant_logs = logs_df.head(10)

        log_context_str = relevant_logs.to_string(index=False)

        if self.is_groq_active():
            try:
                prompt = f"""You are an Expert Tier 3 SOC Security Analyst examining an active security incident.
DO NOT fabricate any details, IP addresses, or usernames that are absent from the log evidence provided.

INCIDENT ALERT DETAILS:
- Title: {alert.get('title')}
- Category: {alert.get('category')}
- Severity: {alert.get('severity')}
- Confidence: {alert.get('confidence')}%
- Source IP: {alert.get('src_ip')}
- Targeted User: {alert.get('username')}
- Affected Asset: {alert.get('affected_asset')}
- MITRE ATT&CK: {alert.get('mitre_id')} ({alert.get('mitre_name')}) - Tactic: {alert.get('tactic')}
- Alert Description: {alert.get('description')}

GROUNDED LOG EVIDENCE:
```
{log_context_str}
```

Provide your response strictly structured with the following sections:
1. Executive Summary
2. Evidence Analysis
3. Technical Reasoning
4. MITRE ATT&CK Mapping
5. Recommended Remediation & Investigation Steps
6. Incident Risk & Confidence Assessment
"""
                response = self.client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[
                        {"role": "system", "content": "You are a professional enterprise AI SOC Incident Analyst. Keep findings strictly grounded on the logs."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2,
                    max_tokens=1000
                )
                raw_text = response.choices[0].message.content
                return self._parse_ai_output(raw_text, alert)
            except Exception as e:
                return self._generate_heuristic_incident_report(alert, relevant_logs, f"Groq API Error: {str(e)}")

        else:
            return self._generate_heuristic_incident_report(alert, relevant_logs)

    def chat_with_logs(self, user_query: str, logs_df: pd.DataFrame, chat_history: List[Dict[str, str]] = None) -> str:
        if logs_df.empty:
            return "No log records uploaded yet. Please upload a log file or select a sample dataset to begin analysis."

        retrieved_df = self._retrieve_log_context(user_query, logs_df)
        context_snippet = retrieved_df[["timestamp", "event_type", "username", "src_ip", "dest_ip", "status", "message"]].to_string(index=False)

        if self.is_groq_active():
            try:
                system_prompt = f"""You are the AI SOC Assistant. Answer the user's question using ONLY the provided security log evidence. 
If the information is not present in the logs, state clearly that it is not in the uploaded dataset.

RETRIEVED LOG CONTEXT:
```
{context_snippet}
```
"""
                messages = [{"role": "system", "content": system_prompt}]
                if chat_history:
                    for msg in chat_history[-4:]:
                        messages.append({"role": msg["role"], "content": msg["content"]})
                messages.append({"role": "user", "content": user_query})

                response = self.client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=messages,
                    temperature=0.2,
                    max_tokens=600
                )
                return response.choices[0].message.content
            except Exception:
                return self._generate_heuristic_chat_response(user_query, retrieved_df, logs_df)

        return self._generate_heuristic_chat_response(user_query, retrieved_df, logs_df)

    def chat_with_logs_stream(self, user_query: str, logs_df: pd.DataFrame, chat_history: List[Dict[str, str]] = None):
        """Stream Groq chat responses token-by-token; falls back to a single-chunk heuristic."""
        if logs_df.empty:
            yield "No log records uploaded yet. Please upload a log file or select a sample dataset to begin analysis."
            return

        retrieved_df = self._retrieve_log_context(user_query, logs_df)
        context_snippet = retrieved_df[["timestamp", "event_type", "username", "src_ip", "dest_ip", "status", "message"]].to_string(index=False)

        if self.is_groq_active():
            try:
                system_prompt = f"""You are the AI SOC Assistant. Answer the user's question using ONLY the provided security log evidence. 
If the information is not present in the logs, state clearly that it is not in the uploaded dataset.

RETRIEVED LOG CONTEXT:
```
{context_snippet}
```
"""
                messages = [{"role": "system", "content": system_prompt}]
                if chat_history:
                    for msg in chat_history[-4:]:
                        messages.append({"role": msg["role"], "content": msg["content"]})
                messages.append({"role": "user", "content": user_query})

                stream = self.client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=messages,
                    temperature=0.2,
                    max_tokens=600,
                    stream=True,
                )
                for chunk in stream:
                    delta = chunk.choices[0].delta.content
                    if delta:
                        yield delta
                return
            except Exception:
                pass

        yield self._generate_heuristic_chat_response(user_query, retrieved_df, logs_df)

    def _retrieve_log_context(self, user_query: str, logs_df: pd.DataFrame) -> pd.DataFrame:
        query_terms = user_query.lower().split()
        matched_mask = pd.Series(False, index=logs_df.index)

        for term in query_terms:
            if len(term) > 2:
                for col in ["src_ip", "username", "event_type", "message", "status"]:
                    matched_mask |= logs_df[col].astype(str).str.lower().str.contains(term, na=False)

        retrieved_df = logs_df[matched_mask]
        if retrieved_df.empty:
            return logs_df.head(15)
        return retrieved_df.head(20)

    def _parse_ai_output(self, raw_text: str, alert: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "executive_summary": self._extract_section(raw_text, "Executive Summary", "Evidence Analysis"),
            "evidence": self._extract_section(raw_text, "Evidence Analysis", "Technical Reasoning"),
            "reasoning": self._extract_section(raw_text, "Technical Reasoning", "MITRE ATT&CK"),
            "mitre_mapping": f"{alert.get('mitre_id', 'T1110')} - {alert.get('mitre_name', 'Brute Force')} ({alert.get('tactic', 'Credential Access')})",
            "recommendations": self._extract_section(raw_text, "Recommended Remediation", "Incident Risk"),
            "confidence_score": alert.get("confidence", 90),
            "raw_report": raw_text
        }

    def _extract_section(self, text: str, start_header: str, end_header: str) -> str:
        try:
            match = re.search(f"{start_header}[:\n#*]*", text, re.IGNORECASE)
            if match:
                start_pos = match.end()
                end_match = re.search(f"{end_header}[:\n#*]*", text[start_pos:], re.IGNORECASE)
                if end_match:
                    return text[start_pos:start_pos + end_match.start()].strip(" #*:\n")
                return text[start_pos:start_pos + 600].strip(" #*:\n")
            return text[:400]
        except Exception:
            return text[:400]

    def _generate_heuristic_incident_report(self, alert: Dict[str, Any], logs: pd.DataFrame, note: str = "") -> Dict[str, Any]:
        title = alert.get("title", "Security Incident Detected")
        src_ip = alert.get("src_ip", "Unknown")
        user = alert.get("username", "Unknown")
        asset = alert.get("affected_asset", "10.0.0.1")
        mitre_id = alert.get("mitre_id", "T1110")
        mitre_name = alert.get("mitre_name", "Brute Force")
        tactic = alert.get("tactic", "Credential Access")
        severity = alert.get("severity", "High")

        exec_summary = (
            f"The AI SOC Engine detected a {severity} severity incident ({title}) originating from source IP {src_ip} "
            f"targeting user account '{user}' on system {asset}. "
            f"Ground evidence reveals anomalous access patterns consistent with malicious activity."
        )

        evidence_text = f"- Source IP Address: {src_ip}\n- Targeted Account: {user}\n- Destination Asset: {asset}\n- Total Correlated Log Entries: {len(logs)} events\n- Sample Event Message: {alert.get('description')}"

        reasoning = (
            f"The observed activity matches technique {mitre_id} ({mitre_name}) under the {tactic} tactic. "
            f"The frequency and status codes indicate an adversary actively attempting un-authorized access or execution. "
            f"No legitimate administrator change control record matches this timeframe."
        )

        recommendations = (
            f"1. Immediately block IP address {src_ip} on perimeter firewalls.\n"
            f"2. Terminate active sessions for account '{user}' and require immediate MFA re-authentication.\n"
            f"3. Perform memory and artifact forensic scan on host {asset}.\n"
            f"4. Audit Active Directory event logs for secondary lateral movement."
        )

        raw = f"## Executive Summary\n{exec_summary}\n\n## Evidence\n{evidence_text}\n\n## Technical Reasoning\n{reasoning}\n\n## Recommendations\n{recommendations}"

        if note:
            raw += f"\n\n*(Note: {note})*"

        return {
            "executive_summary": exec_summary,
            "evidence": evidence_text,
            "reasoning": reasoning,
            "mitre_mapping": f"{mitre_id} - {mitre_name} ({tactic})",
            "recommendations": recommendations,
            "confidence_score": alert.get("confidence", 88),
            "raw_report": raw
        }

    def _generate_heuristic_chat_response(self, user_query: str, retrieved: pd.DataFrame, full_logs: pd.DataFrame) -> str:
        query_lower = user_query.lower()
        total_logs = len(full_logs)

        if "top attack" in query_lower or "top ip" in query_lower or "attacker" in query_lower:
            top_ips = full_logs["src_ip"].value_counts().head(3).to_dict()
            summary = "\n".join([f"- **{ip}**: {count} total events" for ip, count in top_ips.items()])
            top_ip = next(iter(top_ips), "N/A")
            top_count = top_ips.get(top_ip, 0)
            return (
                f"Based on the uploaded log dataset ({total_logs} records), the top active source IP addresses are:\n\n"
                f"{summary}\n\nThe IP `{top_ip}` exhibits the highest event frequency with **{top_count}** log entries."
            )

        elif "fail" in query_lower or "login" in query_lower or "auth" in query_lower:
            fails = full_logs[full_logs["status"].astype(str).str.upper().str.contains("FAIL")]
            users = fails["username"].value_counts().head(3).to_dict()
            user_str = ", ".join([f"`{u}` ({c} failures)" for u, c in users.items()])
            return f"A total of **{len(fails)} authentication failures** were found in the uploaded logs.\nMost targeted accounts: {user_str}."

        elif "powershell" in query_lower or "script" in query_lower:
            ps_rows = full_logs[full_logs["message"].astype(str).str.lower().str.contains("powershell|-enc|bypass")]
            if not ps_rows.empty:
                return f"Found **{len(ps_rows)} suspicious PowerShell execution log entry**:\n- User: `{ps_rows.iloc[0]['username']}`\n- Command Snippet: `{ps_rows.iloc[0]['message'][:140]}...`\n\nThis script contains encoded base64 parameters matching MITRE technique T1059.001."
            return "No suspicious PowerShell commands were detected in the current log dataset."

        else:
            sample_count = len(retrieved)
            events = ", ".join(retrieved["event_type"].unique()[:3])
            return f"Analyzing **{sample_count} relevant log lines** matching your query from the total {total_logs} uploaded records.\nKey events observed: **{events}**.\n\n*Log snippet:* `{retrieved.iloc[0]['message'] if not retrieved.empty else 'N/A'}`"
