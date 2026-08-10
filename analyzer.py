"""
Rule-Based Threat Detection Engine for AI SOC Assistant.
Detects 9 core security incident vectors and formats standardized alerts.
"""

import re
from typing import List, Dict, Any
import pandas as pd
from config import THRESHOLDS, MITRE_ATTACK_DB, BUSINESS_HOURS
from utils import get_ip_location, is_internal_location


class SOCAnalyzer:
    """Core rule-based detection engine for normalized security logs."""

    def __init__(self, thresholds: Dict[str, Any] = None):
        self.thresholds = dict(thresholds or THRESHOLDS)

    def run_all_detections(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        if df.empty:
            return []

        alerts = []
        alerts.extend(self._detect_brute_force(df))
        alerts.extend(self._detect_port_scanning(df))
        alerts.extend(self._detect_multiple_failed_logins(df))
        alerts.extend(self._detect_account_lockouts(df))
        alerts.extend(self._detect_privilege_escalation(df))
        alerts.extend(self._detect_suspicious_powershell(df))
        alerts.extend(self._detect_excessive_failed_auth(df))
        alerts.extend(self._detect_impossible_travel(df))
        alerts.extend(self._detect_anomalous_login_behavior(df))

        alerts = self._deduplicate_alerts(alerts)

        severity_weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        for idx, alert in enumerate(alerts, 1):
            alert["alert_id"] = f"ALT-{idx:04d}"

        alerts.sort(key=lambda x: severity_weights.get(x["severity"], 0), reverse=True)
        return alerts

    def _windowed_group(self, group: pd.DataFrame, window_min: int) -> pd.DataFrame:
        """Return rows within the configured time window ending at the group's latest event."""
        if group.empty:
            return group
        group = group.sort_values("timestamp")
        latest = group["timestamp"].max()
        window_start = latest - pd.Timedelta(minutes=window_min)
        return group[group["timestamp"] >= window_start]

    def _deduplicate_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge overlapping alerts that share source IP and category."""
        severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        merged: Dict[tuple, Dict[str, Any]] = {}

        for alert in alerts:
            key = (alert.get("src_ip"), alert.get("category"))
            if key not in merged:
                merged[key] = alert
                continue

            existing = merged[key]
            if severity_rank.get(alert["severity"], 0) > severity_rank.get(existing["severity"], 0):
                existing["severity"] = alert["severity"]
                existing["confidence"] = max(existing.get("confidence", 0), alert.get("confidence", 0))
            existing["description"] = existing["description"] + " | " + alert["description"]
            existing_evidence = existing.get("evidence", [])
            new_evidence = alert.get("evidence", [])
            if isinstance(existing_evidence, list) and isinstance(new_evidence, list):
                existing["evidence"] = (existing_evidence + new_evidence)[:20]

        return list(merged.values())

    def _detect_brute_force(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        alerts = []
        failures = df[df["status"].astype(str).str.upper().str.contains("FAIL|REJECT|DENY", na=False)]
        if failures.empty:
            return alerts

        window_min = self.thresholds["brute_force_window_min"]
        for ip, group in failures.groupby("src_ip"):
            windowed = self._windowed_group(group, window_min)
            count = len(windowed)
            if count >= self.thresholds["brute_force_attempts"]:
                target_users = list(windowed["username"].unique())
                last_time = windowed["timestamp"].max()

                succ = df[
                    (df["src_ip"] == ip)
                    & (df["status"].astype(str).str.upper() == "SUCCESS")
                    & (df["timestamp"] > windowed["timestamp"].min())
                ]
                is_compromised = not succ.empty

                severity = "Critical" if is_compromised else "High"
                confidence = 95 if is_compromised else 85
                mitre = MITRE_ATTACK_DB["Brute Force"]

                alerts.append({
                    "title": f"SSH/Auth Brute-Force Attack detected from {ip}",
                    "category": "Brute Force",
                    "severity": severity,
                    "confidence": confidence,
                    "src_ip": ip,
                    "username": ", ".join(target_users[:3]),
                    "affected_asset": str(windowed["dest_ip"].iloc[0]),
                    "timestamp": str(last_time),
                    "mitre_id": mitre["id"],
                    "mitre_name": mitre["name"],
                    "tactic": mitre["tactic"],
                    "description": (
                        f"Source IP {ip} generated {count} failed login attempts within {window_min} minutes "
                        f"across targeted accounts ({', '.join(target_users[:3])})."
                        + (" CRITICAL: Followed by a SUCCESSFUL login!" if is_compromised else "")
                    ),
                    "evidence": windowed[["timestamp", "username", "src_ip", "port", "message"]].to_dict(orient="records"),
                    "recommendation": "Block source IP at firewall, mandate immediate password reset for targeted users, and verify MFA status."
                })
        return alerts

    def _detect_port_scanning(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        alerts = []
        scan_df = df[df["event_type"].astype(str).str.upper().str.contains("SCAN|SYN|PROBE", na=False)]
        if scan_df.empty:
            return alerts

        window_min = self.thresholds["port_scan_window_min"]
        for ip, group in scan_df.groupby("src_ip"):
            windowed = self._windowed_group(group, window_min)
            unique_ports = windowed["port"].nunique()
            if unique_ports >= self.thresholds["port_scan_distinct_ports"]:
                mitre = MITRE_ATTACK_DB["Port Scanning"]
                alerts.append({
                    "title": f"Reconnaissance Port Scanning from {ip}",
                    "category": "Port Scanning",
                    "severity": "Medium",
                    "confidence": 90,
                    "src_ip": ip,
                    "username": "N/A",
                    "affected_asset": str(windowed["dest_ip"].iloc[0]),
                    "timestamp": str(windowed["timestamp"].max()),
                    "mitre_id": mitre["id"],
                    "mitre_name": mitre["name"],
                    "tactic": mitre["tactic"],
                    "description": (
                        f"Host {ip} probed {unique_ports} distinct network ports within "
                        f"a {window_min}-minute window."
                    ),
                    "evidence": windowed[["timestamp", "src_ip", "dest_ip", "port", "message"]].head(10).to_dict(orient="records"),
                    "recommendation": "Block scanner IP on peripheral firewalls and update IDS/IPS signature rules."
                })
        return alerts

    def _detect_multiple_failed_logins(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        alerts = []
        fails = df[df["status"].astype(str).str.upper().str.contains("FAIL", na=False)]
        window_min = self.thresholds["brute_force_window_min"]
        for user, group in fails.groupby("username"):
            if user in ["N/A", "system", "root"] or len(str(user)) < 2:
                continue
            windowed = self._windowed_group(group, window_min)
            if len(windowed) >= self.thresholds["multiple_failed_logins"]:
                mitre = MITRE_ATTACK_DB["Multiple Failed Logins"]
                alerts.append({
                    "title": f"Repeated Failed Logins for User Account: {user}",
                    "category": "Multiple Failed Logins",
                    "severity": "Medium",
                    "confidence": 80,
                    "src_ip": str(windowed["src_ip"].iloc[0]),
                    "username": user,
                    "affected_asset": str(windowed["dest_ip"].iloc[0]),
                    "timestamp": str(windowed["timestamp"].max()),
                    "mitre_id": mitre["id"],
                    "mitre_name": mitre["name"],
                    "tactic": mitre["tactic"],
                    "description": f"User account '{user}' experienced {len(windowed)} failed authentication attempts within {window_min} minutes.",
                    "evidence": windowed[["timestamp", "username", "src_ip", "message"]].to_dict(orient="records"),
                    "recommendation": "Prompt user for identity verification and check for automated credential spraying."
                })
        return alerts

    def _detect_account_lockouts(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        alerts = []
        lockouts = df[
            df["message"].astype(str).str.lower().str.contains("lockout|locked out|4740", na=False)
            | df["event_type"].astype(str).str.upper().str.contains("LOCKOUT", na=False)
        ]
        for _, row in lockouts.iterrows():
            mitre = MITRE_ATTACK_DB["Account Lockout"]
            alerts.append({
                "title": f"Account Lockout Event: {row['username']}",
                "category": "Account Lockout",
                "severity": "High",
                "confidence": 95,
                "src_ip": str(row["src_ip"]),
                "username": str(row["username"]),
                "affected_asset": str(row["dest_ip"]),
                "timestamp": str(row["timestamp"]),
                "mitre_id": mitre["id"],
                "mitre_name": mitre["name"],
                "tactic": mitre["tactic"],
                "description": f"Account '{row['username']}' was locked out due to repeated security policy violations.",
                "evidence": [row.to_dict()],
                "recommendation": "Verify user identity, inspect originating workstation for cached stale credentials or malware."
            })
        return alerts

    def _detect_privilege_escalation(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        alerts = []
        pe_keywords = ["sudo", "mimikatz", "lsass", "4672", "privilege_escalation", "root grant", "admin privilege"]
        pattern = "|".join([re.escape(k) for k in pe_keywords])
        pe_rows = df[
            df["message"].astype(str).str.lower().str.contains(pattern, na=False)
            | df["event_type"].astype(str).str.upper().str.contains("PRIVILEGE|ELEVATE", na=False)
        ]

        for _, row in pe_rows.iterrows():
            mitre = MITRE_ATTACK_DB["Privilege Escalation"]
            alerts.append({
                "title": f"Privilege Escalation Attempt on {row['dest_ip']} by {row['username']}",
                "category": "Privilege Escalation",
                "severity": "Critical",
                "confidence": 92,
                "src_ip": str(row["src_ip"]),
                "username": str(row["username"]),
                "affected_asset": str(row["dest_ip"]),
                "timestamp": str(row["timestamp"]),
                "mitre_id": mitre["id"],
                "mitre_name": mitre["name"],
                "tactic": mitre["tactic"],
                "description": f"Potential privilege escalation activity detected on host {row['dest_ip']}. Message: {row['message']}",
                "evidence": [row.to_dict()],
                "recommendation": "Isolate host from local network immediately, dump system memory for forensics, and rotate kerberos krbtgt keys."
            })
        return alerts

    def _detect_suspicious_powershell(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        alerts = []
        ps_keywords = ["-enc", "-encodedcommand", "executionpolicy bypass", "downloadstring", "iex", "invoke-obfuscation"]
        pattern = "|".join([re.escape(k) for k in ps_keywords])
        ps_rows = df[df["message"].astype(str).str.lower().str.contains(pattern, na=False)]

        for _, row in ps_rows.iterrows():
            mitre = MITRE_ATTACK_DB["Suspicious PowerShell"]
            alerts.append({
                "title": f"Suspicious Encoded PowerShell Execution by {row['username']}",
                "category": "Suspicious PowerShell",
                "severity": "Critical",
                "confidence": 98,
                "src_ip": str(row["src_ip"]),
                "username": str(row["username"]),
                "affected_asset": str(row["dest_ip"]),
                "timestamp": str(row["timestamp"]),
                "mitre_id": mitre["id"],
                "mitre_name": mitre["name"],
                "tactic": mitre["tactic"],
                "description": f"PowerShell executed with bypass flags or base64 encoded payload: {row['message'][:120]}...",
                "evidence": [row.to_dict()],
                "recommendation": "Decode base64 command, terminate parent process ID, inspect network sockets for active C2 beaconing."
            })
        return alerts

    def _detect_excessive_failed_auth(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        alerts = []
        fails = df[df["status"].astype(str).str.upper().str.contains("FAIL", na=False)]
        window_min = self.thresholds["brute_force_window_min"]
        windowed = self._windowed_group(fails, window_min) if not fails.empty else fails
        if len(windowed) >= self.thresholds["excessive_failed_auth_surge"]:
            mitre = MITRE_ATTACK_DB["Excessive Failed Auth"]
            alerts.append({
                "title": "Network-Wide Authentication Failure Surge (Possible Password Spray)",
                "category": "Excessive Failed Auth",
                "severity": "High",
                "confidence": 85,
                "src_ip": "Multiple IPs",
                "username": "Multiple Accounts",
                "affected_asset": "Identity Infrastructure",
                "timestamp": str(windowed["timestamp"].max()),
                "mitre_id": mitre["id"],
                "mitre_name": mitre["name"],
                "tactic": mitre["tactic"],
                "description": f"A network-wide total of {len(windowed)} authentication failures was recorded within {window_min} minutes.",
                "evidence": windowed[["timestamp", "username", "src_ip", "message"]].head(10).to_dict(orient="records"),
                "recommendation": "Enable CAPTCHA / Smart Lockout rules on identity gateways and monitor for IP pool rotation."
            })
        return alerts

    def _detect_impossible_travel(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        alerts = []
        user_groups = df.groupby("username")
        for user, group in user_groups:
            if user in ["N/A", "system", "root"] or len(group) < 2:
                continue

            rows = group.sort_values(by="timestamp").to_dict(orient="records")
            for i in range(len(rows) - 1):
                r1, r2 = rows[i], rows[i + 1]
                t1, t2 = r1["timestamp"], r2["timestamp"]
                ip1, ip2 = str(r1["src_ip"]), str(r2["src_ip"])

                if ip1 != ip2:
                    loc1 = get_ip_location(ip1)["country"]
                    loc2 = get_ip_location(ip2)["country"]

                    if not is_internal_location(loc1) and not is_internal_location(loc2) and loc1 != loc2:
                        if isinstance(t1, str):
                            t1 = pd.to_datetime(t1)
                        if isinstance(t2, str):
                            t2 = pd.to_datetime(t2)

                        diff_hours = abs((t2 - t1).total_seconds()) / 3600.0
                        if diff_hours <= self.thresholds["impossible_travel_max_hours"]:
                            mitre = MITRE_ATTACK_DB["Impossible Travel"]
                            alerts.append({
                                "title": f"Impossible Travel Anomaly: {user} ({loc1} → {loc2})",
                                "category": "Impossible Travel",
                                "severity": "High",
                                "confidence": 92,
                                "src_ip": f"{ip1} / {ip2}",
                                "username": user,
                                "affected_asset": str(r2["dest_ip"]),
                                "timestamp": str(t2),
                                "mitre_id": mitre["id"],
                                "mitre_name": mitre["name"],
                                "tactic": mitre["tactic"],
                                "description": f"User '{user}' logged in from {loc1} ({ip1}) and {loc2} ({ip2}) within {diff_hours * 60:.1f} minutes.",
                                "evidence": [r1, r2],
                                "recommendation": "Revoke active OAuth tokens, force password reset, and prompt user to verify session legitimacy."
                            })
        return alerts

    def _detect_anomalous_login_behavior(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        alerts = []
        start_hour = BUSINESS_HOURS["start"]
        end_hour = BUSINESS_HOURS["end"]

        success = df[
            (df["status"].astype(str).str.upper() == "SUCCESS")
            & (~df["username"].isin(["N/A", "system"]))
        ]
        if success.empty:
            return alerts

        timestamps = pd.to_datetime(success["timestamp"], errors="coerce")
        hours = timestamps.dt.hour
        off_hours_mask = (hours < start_hour) | (hours >= end_hour)
        off_hours = success[off_hours_mask]

        for _, row in off_hours.iterrows():
            ts = pd.to_datetime(row["timestamp"])
            mitre = MITRE_ATTACK_DB["Anomalous Login Behavior"]
            alerts.append({
                "title": f"Off-Hours Successful Access by {row['username']}",
                "category": "Anomalous Login Behavior",
                "severity": "Low",
                "confidence": 70,
                "src_ip": str(row["src_ip"]),
                "username": str(row["username"]),
                "affected_asset": str(row["dest_ip"]),
                "timestamp": str(ts),
                "mitre_id": mitre["id"],
                "mitre_name": mitre["name"],
                "tactic": mitre["tactic"],
                "description": (
                    f"User {row['username']} established a successful session at {ts.strftime('%H:%M:%S')} "
                    f"(outside business hours {start_hour:02d}:00–{end_hour:02d}:00)."
                ),
                "evidence": [row.to_dict()],
                "recommendation": "Confirm whether scheduled maintenance was planned for user."
            })
        return alerts
