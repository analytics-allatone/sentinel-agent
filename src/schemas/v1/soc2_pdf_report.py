from io import BytesIO
from datetime import datetime, timezone

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable,
)

NAVY  = colors.HexColor("#0C447C")
SLATE = colors.HexColor("#3d3d3a")
MUTED = colors.HexColor("#73726c")
LINE  = colors.HexColor("#D3D1C7")
ALT   = colors.HexColor("#F5F7FA")
RED   = colors.HexColor("#A32D2D")
AMBER = colors.HexColor("#854F0B")
GREEN = colors.HexColor("#3B6D11")
SEV = {"critical": RED, "high": RED, "medium": AMBER, "low": GREEN, "info": MUTED}

# Per-domain rendering config. Order = order of sections in the PDF.
# summary_kpis: (label, key) pairs pulled from that domain's `summary` dict.
# breakdowns:   (heading, data-key) for the list[{label,count}] blocks to show.
# notable_cols: (header, row-key) for the notable_events table columns.
DOMAINS = [
    ("auth", "Authentication &amp; access control (CC6.1)", {
        "kpis": [("Total", "total_auth_events"), ("Successful", "successful_auths"),
                 ("Failed", "failed_auths"), ("Failure rate %", "failure_rate_pct"),
                 ("Unique users", "unique_users"), ("Unique source IPs", "unique_source_ips"),
                 ("Privileged actions", "privileged_actions"), ("High severity", "high_severity_events")],
        "breakdowns": [("Failed logins by user", "failed_by_user"),
                       ("Failed logins by source IP", "failed_by_source_ip"),
                       ("Failure reasons", "failure_reasons")],
        "notable": [("Time", "timestamp"), ("User", "username"), ("Action", "action"),
                    ("Outcome", "outcome"), ("Severity", "severity"),
                    ("Source IP", "source_ip"), ("Reason", "failure_reason")],
    }),
    ("file", "File integrity &amp; change management (CC7.1)", {
        "kpis": [("Total", "total_file_events"), ("Unique files", "unique_files"),
                 ("Unique users", "unique_users"), ("Anomalies", "anomalies"),
                 ("IOC matches", "ioc_matches"), ("High severity", "high_severity_events"),
                 ("Max risk", "max_risk_score"), ("Avg risk", "avg_risk_score")],
        "breakdowns": [("Top actions", "top_actions"), ("Top directories", "top_directories"),
                       ("MITRE techniques", "mitre_techniques")],
        "notable": [("Time", "timestamp"), ("Action", "action"), ("File", "file_path"),
                    ("User", "user_name"), ("Severity", "severity"), ("Risk", "risk_score")],
    }),
    ("network", "Network boundary protection (CC6.6)", {
        "kpis": [("Total", "total_network_events"), ("Unique dest IPs", "unique_dest_ips"),
                 ("Unique DNS", "unique_dns_queries"), ("Bytes sent", "total_bytes_sent"),
                 ("Bytes received", "total_bytes_received"), ("Anomalies", "anomalies"),
                 ("IOC matches", "ioc_matches"), ("High severity", "high_severity_events")],
        "breakdowns": [("Top destination IPs", "top_dest_ips"),
                       ("Top destination ports", "top_dest_ports"),
                       ("External connections", "external_connections")],
        "notable": [("Time", "timestamp"), ("Dir", "direction"), ("Proto", "protocol"),
                    ("Dest IP", "dest_ip"), ("Port", "dest_port"),
                    ("Severity", "severity"), ("Risk", "risk_score")],
    }),
    ("process", "Process execution &amp; malicious-code monitoring (CC7.2)", {
        "kpis": [("Total", "total_process_events"), ("Unique procs", "unique_processes"),
                 ("Unique execs", "unique_executables"), ("Anomalies", "anomalies"),
                 ("IOC matches", "ioc_matches"), ("High severity", "high_severity_events"),
                 ("Avg CPU %", "avg_cpu_percent"), ("Max risk", "max_risk_score")],
        "breakdowns": [("Top processes", "top_process_names"), ("Top users", "top_users"),
                       ("MITRE techniques", "mitre_techniques")],
        "notable": [("Time", "timestamp"), ("Process", "process_name"), ("User", "user"),
                    ("Severity", "severity"), ("Outcome", "outcome"), ("Risk", "risk_score")],
    }),
    ("usb", "Removable media &amp; data transfer (CC6.7)", {
        "kpis": [("Total", "total_usb_events"), ("Unique devices", "unique_devices"),
                 ("Unique vendors", "unique_vendors"), ("Bytes transferred", "total_bytes_transferred"),
                 ("Anomalies", "anomalies"), ("IOC matches", "ioc_matches"),
                 ("High severity", "high_severity_events"), ("Max risk", "max_risk_score")],
        "breakdowns": [("Top vendors", "top_vendors"), ("Top devices", "top_devices"),
                       ("Actions", "top_actions")],
        "notable": [("Time", "timestamp"), ("Action", "action"), ("Vendor", "vendor"),
                    ("Serial", "serial_number"), ("File", "file_name"),
                    ("Severity", "severity"), ("Risk", "risk_score")],
    }),
]

NOTABLE_CAP = 15
BREAKDOWN_CAP = 8


def _styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle("CoverTitle", parent=s["Title"], fontSize=26, textColor=NAVY, leading=30))
    s.add(ParagraphStyle("CoverSub", parent=s["Normal"], fontSize=11, textColor=MUTED,
                         alignment=1, spaceAfter=2))
    s.add(ParagraphStyle("H2", parent=s["Heading2"], fontSize=13, textColor=NAVY,
                         spaceBefore=14, spaceAfter=4))
    s.add(ParagraphStyle("H3", parent=s["Heading3"], fontSize=10, textColor=SLATE, spaceBefore=8, spaceAfter=2))
    s.add(ParagraphStyle("Body", parent=s["Normal"], fontSize=9.5, textColor=SLATE, leading=14, spaceAfter=6))
    s.add(ParagraphStyle("Cell", parent=s["Normal"], fontSize=7.5, leading=9.5, textColor=SLATE))
    s.add(ParagraphStyle("CellH", parent=s["Normal"], fontSize=7.5, leading=9.5, textColor=colors.white))
    s.add(ParagraphStyle("KpiVal", parent=s["Normal"], fontSize=13, textColor=NAVY, alignment=1, leading=15))
    s.add(ParagraphStyle("KpiLab", parent=s["Normal"], fontSize=6.5, textColor=MUTED, alignment=1, leading=8))
    return s


def _fmt(v):
    if v is None:
        return "-"
    if isinstance(v, int) and v >= 100000:
        return f"{v:,}"
    return str(v)


def _kpi_grid(summary, kpis, st):
    cells = []
    for label, key in kpis:
        val = summary.get(key)
        inner = Table([[Paragraph(_fmt(val), st["KpiVal"])], [Paragraph(label, st["KpiLab"])]],
                      colWidths=[40 * mm])
        inner.setStyle(TableStyle([("TOPPADDING", (0, 0), (-1, -1), 1),
                                   ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]))
        cells.append(inner)
    # 4 per row
    rows = [cells[i:i + 4] for i in range(0, len(cells), 4)]
    for r in rows:
        while len(r) < 4:
            r.append("")
    t = Table(rows, colWidths=[42.5 * mm] * 4)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def _breakdown(title, items, st):
    items = (items or [])[:BREAKDOWN_CAP]
    head = [Paragraph(f"<b>{title}</b>", st["CellH"]), Paragraph("<b>#</b>", st["CellH"])]
    body = [[Paragraph(str(i.get("label", "-"))[:40], st["Cell"]),
             Paragraph(str(i.get("count", 0)), st["Cell"])] for i in items] or \
           [[Paragraph("None", st["Cell"]), Paragraph("0", st["Cell"])]]
    t = Table([head] + body, colWidths=[46 * mm, 10 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ALT]),
        ("GRID", (0, 0), (-1, -1), 0.3, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _notable(cols, rows, st):
    rows = (rows or [])[:NOTABLE_CAP]
    header = [Paragraph(f"<b>{h}</b>", st["CellH"]) for h, _ in cols]
    data = [header]
    for r in rows:
        line = []
        for _, key in cols:
            v = r.get(key)
            if key == "severity" and v:
                c = SEV.get(str(v).lower(), MUTED)
                line.append(Paragraph(f'<font color="#{c.hexval()[2:]}">{v}</font>', st["Cell"]))
            else:
                s = "" if v is None else str(v)
                if key == "timestamp" and len(s) > 16:
                    s = s[:16]
                line.append(Paragraph(s[:38], st["Cell"]))
        data.append(line)
    if not rows:
        data.append([Paragraph("No high-severity events.", st["Cell"])] + [""] * (len(cols) - 1))
    n = len(cols)
    w = 170 / n
    t = Table(data, colWidths=[w * mm] * n, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ALT]),
        ("GRID", (0, 0), (-1, -1), 0.3, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(20 * mm, 12 * mm, "CONFIDENTIAL — SOC 2 security evidence report")
    canvas.drawRightString(190 * mm, 12 * mm, f"Page {doc.page}")
    canvas.setStrokeColor(LINE)
    canvas.line(20 * mm, 15 * mm, 190 * mm, 15 * mm)
    canvas.restoreState()


def _scope_table(agent: dict, st):
    meta = [("Agent name", agent.get("agent_name", "-")), ("Agent ID", agent.get("id", "-")),
            ("Host name", agent.get("host_name", "-")),
            ("Operating system", f'{agent.get("os","-")} {agent.get("release","")}'),
            ("Primary IP", agent.get("main_ip", "-")), ("Status", agent.get("status", "-"))]
    mt = Table([[Paragraph(f"<b>{k}</b>", st["Cell"]), Paragraph(str(v), st["Cell"])] for k, v in meta],
               colWidths=[45*mm, 120*mm])
    mt.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
                            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return mt


def _agent_sections(agent: dict, reports: dict, st) -> list:
    """The per-agent body: scope table + one block per domain. Reused by both the
    single-agent and the fleet (all-agents) builders."""
    flow = [Paragraph(f'Agent: {agent.get("agent_name","-")} '
                      f'(ID {agent.get("id","-")}, host {agent.get("host_name","-")})', st["H2"]),
            HRFlowable(width="100%", color=LINE, thickness=0.5, spaceAfter=6),
            _scope_table(agent, st)]
    for key, title, cfg in DOMAINS:
        data = reports.get(key)
        if not data:
            continue
        summary = data.get("summary", {})
        flow += [Spacer(1, 8), Paragraph(title, st["H2"]),
                 HRFlowable(width="100%", color=LINE, thickness=0.5, spaceAfter=4),
                 _kpi_grid(summary, cfg["kpis"], st), Spacer(1, 6)]
        blocks = [_breakdown(h, data.get(k), st) for h, k in cfg["breakdowns"]]
        while len(blocks) < 3:
            blocks.append("")
        bt = Table([blocks], colWidths=[56.6*mm]*3)
        bt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]))
        flow += [bt, Spacer(1, 6),
                 Paragraph("Notable events (high / critical)", st["H3"]),
                 _notable(cfg["notable"], data.get("notable_events"), st)]
    return flow


def _fleet_overview(agents_data: list, st):
    """One row per agent with headline counts across all domains — the 'all agents
    at a glance' table on the fleet report."""
    head = ["Agent", "ID", "Host", "Auth", "Failed", "File", "Network", "Process", "USB", "High-sev"]
    header = [Paragraph(f"<b>{h}</b>", st["CellH"]) for h in head]
    data = [header]

    def tot(rep, domain, key):
        d = (rep.get(domain) or {}).get("summary", {}) if rep else {}
        return d.get(key, 0) or 0

    for entry in agents_data:
        ag, rep = entry["agent"], entry["reports"]
        high = sum(tot(rep, dom, "high_severity_events")
                   for dom in ("auth", "file", "network", "process", "usb"))
        data.append([
            Paragraph(str(ag.get("agent_name", "-"))[:22], st["Cell"]),
            Paragraph(str(ag.get("id", "-")), st["Cell"]),
            Paragraph(str(ag.get("host_name", "-"))[:16], st["Cell"]),
            Paragraph(str(tot(rep, "auth", "total_auth_events")), st["Cell"]),
            Paragraph(str(tot(rep, "auth", "failed_auths")), st["Cell"]),
            Paragraph(str(tot(rep, "file", "total_file_events")), st["Cell"]),
            Paragraph(str(tot(rep, "network", "total_network_events")), st["Cell"]),
            Paragraph(str(tot(rep, "process", "total_process_events")), st["Cell"]),
            Paragraph(str(tot(rep, "usb", "total_usb_events")), st["Cell"]),
            Paragraph(str(high), st["Cell"]),
        ])
    t = Table(data, repeatRows=1,
              colWidths=[w * mm for w in (30, 10, 24, 15, 15, 15, 18, 18, 12, 15)])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ALT]),
        ("GRID", (0, 0), (-1, -1), 0.3, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def build_fleet_soc2_pdf(agents_data: list, window: dict) -> bytes: #, generated_by: str) -> bytes:
    """
    All agents in ONE pdf.
    agents_data: [ {"agent": {...}, "reports": {"auth":..., ...}}, ... ]
    Renders: cover -> fleet overview table (one row per agent) -> per-agent detail.
    """
    st = _styles()
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20*mm, rightMargin=20*mm,
                            topMargin=18*mm, bottomMargin=22*mm, title="SOC 2 Fleet Evidence Report")
    story = [Spacer(1, 45*mm),
             Paragraph("SOC 2 Security Evidence Report", st["CoverTitle"]),
             Spacer(1, 4),
             Paragraph("Fleet report — all monitored agents", st["CoverSub"]),
             Spacer(1, 8*mm),
             Paragraph(f'Agents in scope: <b>{len(agents_data)}</b>', st["CoverSub"]),
             Paragraph(f'Reporting period: {window["start"]} — {window["end"]}', st["CoverSub"]),
             Paragraph(f'Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}', # by {generated_by}',
                       st["CoverSub"]),
             PageBreak(),
             Paragraph("Fleet overview", st["H2"]),
             HRFlowable(width="100%", color=LINE, thickness=0.5, spaceAfter=6),
             Paragraph("Every monitored agent with headline event counts for the period. "
                       "Detailed per-agent sections follow.", st["Body"]),
             Spacer(1, 4),
             _fleet_overview(agents_data, st)]

    for entry in agents_data:
        story.append(PageBreak())
        story += _agent_sections(entry["agent"], entry["reports"], st)

    doc.build(story, onLaterPages=_footer)
    return buf.getvalue()


def build_soc2_pdf(agent: dict, window: dict, reports: dict) -> bytes:
    """
    agent:   {agent_name, id, host_name, os, release, main_ip, mac_address, status}
    window:  {"start": str, "end": str}
    reports: {"auth": <data dict>, "file": ..., "network": ..., "process": ..., "usb": ...}
             each is the `data` dict your soc2_*_report() functions return. Any may be missing.
    """
    st = _styles()
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20*mm, rightMargin=20*mm,
                            topMargin=18*mm, bottomMargin=22*mm, title="SOC 2 Evidence Report")
    story = []

    # ── cover ──
    story += [Spacer(1, 45*mm),
              Paragraph("SOC 2 Security Evidence Report", st["CoverTitle"]),
              Spacer(1, 4),
              Paragraph("Trust Services Criteria — Security &amp; Monitoring", st["CoverSub"]),
              Spacer(1, 8*mm),
              Paragraph(f'Agent: <b>{agent.get("agent_name","-")}</b> '
                        f'(host {agent.get("host_name","-")}, {agent.get("os","-")} {agent.get("release","")})',
                        st["CoverSub"]),
              Paragraph(f'Reporting period: {window["start"]} — {window["end"]}', st["CoverSub"]),
              Paragraph(f'Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}', # by {generated_by}',
                        st["CoverSub"]),
              PageBreak()]

    # ── scope ──
    story += [Paragraph("System description &amp; scope", st["H2"]),
              HRFlowable(width="100%", color=LINE, thickness=0.5, spaceAfter=6),
              Paragraph("This report presents security-relevant activity captured by the Sentinel "
                        "monitoring agent for the in-scope host over the reporting period. Each "
                        "section maps to a Trust Services Criterion the collected telemetry can "
                        "evidence. Figures are computed from immutable event records.", st["Body"])]
    meta = [("Agent name", agent.get("agent_name", "-")), ("Agent ID", agent.get("id", "-")),
            ("Host name", agent.get("host_name", "-")),
            ("Operating system", f'{agent.get("os","-")} {agent.get("release","")}'),
            ("Primary IP", agent.get("main_ip", "-")), ("Status", agent.get("status", "-"))]
    mt = Table([[Paragraph(f"<b>{k}</b>", st["Cell"]), Paragraph(str(v), st["Cell"])] for k, v in meta],
               colWidths=[45*mm, 120*mm])
    mt.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
                            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    story += [Spacer(1, 4), mt]

    # ── domain sections ──
    for key, title, cfg in DOMAINS:
        data = reports.get(key)
        if not data:
            continue
        summary = data.get("summary", {})
        story += [Spacer(1, 8), Paragraph(title, st["H2"]),
                  HRFlowable(width="100%", color=LINE, thickness=0.5, spaceAfter=4),
                  _kpi_grid(summary, cfg["kpis"], st), Spacer(1, 6)]

        # breakdowns side by side (3 across)
        blocks = [_breakdown(h, data.get(k), st) for h, k in cfg["breakdowns"]]
        while len(blocks) < 3:
            blocks.append("")
        bt = Table([blocks], colWidths=[56.6*mm]*3)
        bt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]))
        story += [bt, Spacer(1, 6),
                  Paragraph("Notable events (high / critical)", st["H3"]),
                  _notable(cfg["notable"], data.get("notable_events"), st)]

    doc.build(story, onLaterPages=_footer)
    return buf.getvalue()