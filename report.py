"""
PDF Incident Report Generator using ReportLab.
Produces professional enterprise security reports ready for download.
"""

import io
from datetime import datetime
from typing import List, Dict, Any
import pandas as pd

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def generate_pdf_report(
    incident_summary: Dict[str, Any],
    alerts: List[Dict[str, Any]],
    logs_df: pd.DataFrame,
    title: str = "Enterprise AI SOC Security Incident Report"
) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0B0F14'),
        spaceAfter=10
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor('#64748B'),
        spaceAfter=15
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#131A23'),
        spaceBefore=14,
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor('#1E293B'),
        spaceAfter=8
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    table_body_style = ParagraphStyle(
        'TableBody',
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#0F172A')
    )

    story = []

    story.append(Paragraph(title, title_style))
    report_id = f"SOC-RPT-{datetime.now().strftime('%Y%m%d-%H%M')}"
    story.append(Paragraph(f"<b>Report ID:</b> {report_id} | <b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | <b>Classification:</b> CONFIDENTIAL", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#22C55E'), spaceAfter=15))

    exec_text = incident_summary.get("executive_summary", "Critical security threats detected requiring immediate SOC triage.")
    story.append(Paragraph("1. Executive Summary", h2_style))
    story.append(Paragraph(exec_text.replace("\n", "<br/>"), body_style))
    story.append(Spacer(1, 10))

    crit_count = sum(1 for a in alerts if a.get("severity") == "Critical")
    high_count = sum(1 for a in alerts if a.get("severity") == "High")
    total_logs = len(logs_df)

    meta_data = [
        [Paragraph("<b>Primary Asset Targeted:</b>", body_style), Paragraph(str(alerts[0].get("affected_asset") if alerts else "Multiple Hosts"), body_style),
         Paragraph("<b>Highest Threat Severity:</b>", body_style), Paragraph(f"<font color='#EF4444'><b>{alerts[0].get('severity') if alerts else 'High'}</b></font>", body_style)],
        [Paragraph("<b>Total Correlated Logs:</b>", body_style), Paragraph(str(total_logs), body_style),
         Paragraph("<b>Critical Alerts Count:</b>", body_style), Paragraph(str(crit_count), body_style)],
        [Paragraph("<b>Primary Attacker IP:</b>", body_style), Paragraph(str(alerts[0].get("src_ip") if alerts else "External"), body_style),
         Paragraph("<b>High Alerts Count:</b>", body_style), Paragraph(str(high_count), body_style)]
    ]

    t_meta = Table(meta_data, colWidths=[130, 140, 130, 140])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 15))

    story.append(Paragraph("2. Correlated Security Alerts", h2_style))
    
    alert_table_data = [[
        Paragraph("Alert ID", table_header_style),
        Paragraph("Severity", table_header_style),
        Paragraph("Category / Vector", table_header_style),
        Paragraph("Source IP", table_header_style),
        Paragraph("Target Account", table_header_style),
        Paragraph("MITRE Ref", table_header_style)
    ]]

    for a in alerts[:8]:
        sev_color = "#EF4444" if a.get("severity") == "Critical" else ("#FB923C" if a.get("severity") == "High" else "#FBBF24")
        alert_table_data.append([
            Paragraph(a.get("alert_id", "ALT-01"), table_body_style),
            Paragraph(f"<font color='{sev_color}'><b>{a.get('severity')}</b></font>", table_body_style),
            Paragraph(a.get("category", "General Threat"), table_body_style),
            Paragraph(a.get("src_ip", "N/A"), table_body_style),
            Paragraph(a.get("username", "N/A"), table_body_style),
            Paragraph(a.get("mitre_id", "T1110"), table_body_style)
        ])

    t_alerts = Table(alert_table_data, colWidths=[60, 60, 130, 110, 100, 80])
    t_alerts.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#334155')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_alerts)
    story.append(Spacer(1, 15))

    story.append(Paragraph("3. MITRE ATT&CK Framework Technique Mapping", h2_style))
    mitre_data = [[
        Paragraph("Technique ID", table_header_style),
        Paragraph("Technique Name", table_header_style),
        Paragraph("Tactic", table_header_style),
        Paragraph("Mitigation Strategy", table_header_style)
    ]]

    seen_mitre = set()
    for a in alerts:
        mid = a.get("mitre_id", "T1110")
        if mid not in seen_mitre:
            seen_mitre.add(mid)
            mitre_data.append([
                Paragraph(f"<b>{mid}</b>", table_body_style),
                Paragraph(a.get("mitre_name", "Brute Force"), table_body_style),
                Paragraph(a.get("tactic", "Credential Access"), table_body_style),
                Paragraph(a.get("recommendation", "Block threat source and enforce MFA")[:120] + "...", table_body_style)
            ])

    t_mitre = Table(mitre_data, colWidths=[80, 130, 110, 220])
    t_mitre.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#334155')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_mitre)
    story.append(Spacer(1, 15))

    story.append(Paragraph("4. Recommended Remediation & Action Plan", h2_style))
    recs = incident_summary.get("recommendations", "1. Block malicious source IPs at firewall level.\n2. Force user credential reset.\n3. Audit host event logs.")
    story.append(Paragraph(recs.replace("\n", "<br/>"), body_style))
    story.append(Spacer(1, 15))

    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#94A3B8'), spaceAfter=10))
    story.append(Paragraph("<i>This document was automatically generated by AI SOC Assistant. Approved for Incident Response Workflow.</i>", subtitle_style))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
