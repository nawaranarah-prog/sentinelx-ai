"""Render report content (dict) to Markdown, standalone HTML (print-ready) and PDF."""

import html
import io
import re

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

SYNTHETIC_NOTE = ("This report was generated from SYNTHETIC demo data (fictional organization Nova Bank). "
                  "It does not describe real events.")


def _ts(v: str | None) -> str:
    return (v or "").replace("T", " ").replace("Z", " UTC")[:23]


def to_markdown(c: dict, generated_at: str) -> str:
    i = c["incident"]
    out = [f"# {c['title']}", "", f"_Generated {generated_at} by {c['generated_by']} · Workspace: {c['workspace']}_", ""]
    if c.get("synthetic_data"):
        out += [f"> **Note:** {SYNTHETIC_NOTE}", ""]
    out += ["## Incident metadata", "", "| Field | Value |", "|---|---|"]
    for k, label in (("number", "Incident"), ("title", "Title"), ("status", "Status"), ("severity", "Severity"),
                     ("confidence", "Confidence"), ("first_seen", "First seen"), ("last_seen", "Last seen"),
                     ("assigned_to", "Assigned to")):
        val = _ts(i[k]) if k in ("first_seen", "last_seen") else i[k]
        out.append(f"| {label} | {val if val not in (None, '') else '—'} |")
    out.append(f"| SentinelX Risk Score | {i['risk_score']}/100 ({i['risk_band']}) |")
    out += ["", "## Summary", "", c["summary"], "", f"**Why these events were correlated:** {c['correlation_reason']}", ""]
    if c.get("ai_summary"):
        a = c["ai_summary"]
        label = f"LIVE AI ({a['provider']} · {a['model']})" if a["mode"] == "LIVE" else "DEMO AI / LOCAL ANALYSIS (no language model)"
        out += [f"## AI summary — {label}", ""] + [f"> {n}" for n in a.get("notices", [])] + ["", a["markdown"], ""]
    imp = c["impact"]
    out += ["## Impact", ""]
    out.append(f"- External data transfer: {imp['external_bytes_human'] or 'none detected'}")
    out.append(f"- Sensitive files accessed: {len(imp['sensitive_files'])}")
    out.append(f"- Privilege escalation observed: {'yes' if imp['privilege_escalation'] else 'no'}")
    aa = c["affected_assets"]
    out += ["", "## Affected assets", "", f"- Users: {', '.join(aa['users']) or '—'}",
            f"- Hosts: {', '.join(h['hostname'] + ' (' + h['criticality'] + ')' for h in aa['hosts']) or '—'}",
            f"- Source IPs: {', '.join(aa['source_ips']) or '—'}",
            f"- External destinations: {', '.join(aa['destination_ips']) or '—'}", "", "## Detections", ""]
    for d in c["detections"]:
        out.append(f"- **[{d['rule_key']} · {d['severity'].upper()} · conf {d['confidence']:.2f}] {d['title']}** ({_ts(d['timestamp'])})")
        if d.get("explanation"):
            out.append(f"  - {d['explanation']}")
        if d.get("evidence_event_uids"):
            out.append(f"  - Evidence: {', '.join(d['evidence_event_uids'])}")
    out += ["", "## MITRE ATT&CK techniques", ""]
    for t in c["techniques"]:
        out.append(f"- **{t['id']} {t['name']}** ({t['tactic']}, mapping confidence {t['mapping_confidence']})"
                   + (f": {t['reason']}" if t.get("reason") else ""))
    r = c["risk"]
    out += ["", f"## Risk score — {r['score']}/100 ({r['band']})", "", f"_{r['disclaimer']}_", "",
            "| Factor | Points | Detail |", "|---|---|---|"]
    out += [f"| {f['factor']} | {f['points']}/{f['max']} | {f['detail']} |" for f in r["factors"]]
    an = c.get("anomalies") or {}
    if an.get("items"):
        out += ["", "## Anomaly analysis", ""]
        for a in an["items"]:
            devs = "; ".join(f"{d['label']}={d['value']:g} (z {d['robust_z']})" for d in a.get("top_deviations", []))
            out.append(f"- {a['entity_type']} {a['entity']} on {a['day']}: IF score {a['if_score']} "
                       f"(threshold {a['if_threshold']}) — {'ANOMALOUS' if a['is_anomalous'] else 'normal'}" + (f"; {devs}" if devs else ""))
    if c["timeline"]:
        out += ["", "## Timeline (evidence events)", "", "| Time (UTC) | Event | Type/Action | User | Host | Detail |",
                "|---|---|---|---|---|---|"]
        for e in c["timeline"]:
            detail = (e["detail"] or "").replace("|", "\\|")[:120]
            out.append(f"| {_ts(e['timestamp'])} | {e['event_uid']} | {e['event_type']}/{e['action'] or ''} "
                       f"{e['status'] or ''} | {e['user'] or ''} | {e['host'] or ''} | {detail} |")
    out += ["", "## Recommendations", ""] + [f"{n}. {x}" for n, x in enumerate(c["recommendations"], 1)]
    if c.get("notes"):
        out += ["", "## Analyst notes", ""] + [f"- {n['created_at']} {n['author']} ({n['kind']}): {n['body']}" for n in c["notes"]]
    if c.get("status_history"):
        out += ["", "## Status history", ""] + [f"- {_ts(h['at'])}: {h['from'] or '—'} → {h['to']} by {h['by']} {h['note']}"
                                                  for h in c["status_history"]]
    return "\n".join(out) + "\n"


def _md_inline(text: str) -> str:
    t = html.escape(text)
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"`(.+?)`", r"<code>\1</code>", t)
    t = re.sub(r"(?<![\w*])_(.+?)_(?!\w)", r"<em>\1</em>", t)
    return t


def md_to_html(md: str) -> str:
    """Minimal, safe Markdown → HTML (all text escaped; supports headings, lists, tables, quotes, bold, code)."""
    lines, out, in_list, in_table = md.split("\n"), [], None, False
    for line in lines:
        if in_table and not line.startswith("|"):
            out.append("</tbody></table>")
            in_table = False
        if in_list and not re.match(r"^\s*(-|\d+\.)\s", line):
            out.append(f"</{in_list}>")
            in_list = None
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(re.fullmatch(r"-+", c) for c in cells if c):
                continue
            if not in_table:
                out.append("<table><tbody>")
                in_table = True
                out.append("<tr>" + "".join(f"<th>{_md_inline(c)}</th>" for c in cells) + "</tr>")
            else:
                out.append("<tr>" + "".join(f"<td>{_md_inline(c)}</td>" for c in cells) + "</tr>")
            continue
        m = re.match(r"^(#{1,4})\s+(.*)", line)
        if m:
            n = len(m.group(1))
            out.append(f"<h{n}>{_md_inline(m.group(2))}</h{n}>")
            continue
        m = re.match(r"^\s*(-|\d+\.)\s+(.*)", line)
        if m:
            tag = "ul" if m.group(1) == "-" else "ol"
            if in_list != tag:
                if in_list:
                    out.append(f"</{in_list}>")
                out.append(f"<{tag}>")
                in_list = tag
            indent = " class=\"sub\"" if line.startswith("  ") else ""
            out.append(f"<li{indent}>{_md_inline(m.group(2))}</li>")
            continue
        if line.startswith(">"):
            out.append(f"<blockquote>{_md_inline(line.lstrip('> '))}</blockquote>")
        elif line.strip():
            out.append(f"<p>{_md_inline(line)}</p>")
    if in_list:
        out.append(f"</{in_list}>")
    if in_table:
        out.append("</tbody></table>")
    return "\n".join(out)


HTML_CSS = """
body{font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1b1f24;max-width:960px;margin:32px auto;
padding:0 24px;line-height:1.5;font-size:14px;background:#fff}
h1{font-size:24px;border-bottom:3px solid #1f3a5f;padding-bottom:8px}h2{font-size:17px;color:#1f3a5f;margin-top:28px;
border-bottom:1px solid #d8dee6;padding-bottom:4px}table{border-collapse:collapse;width:100%;margin:8px 0;font-size:12.5px}
th,td{border:1px solid #d8dee6;padding:5px 8px;text-align:left;vertical-align:top;word-break:break-word}
th{background:#f1f4f8}blockquote{margin:8px 0;padding:8px 12px;background:#fff7e6;border-left:4px solid #d98e04}
code{font-family:Consolas,monospace;font-size:12px;background:#f1f4f8;padding:1px 4px;border-radius:3px}
li.sub{list-style:circle;margin-left:18px;color:#444}.brand{color:#1f3a5f;font-weight:700;letter-spacing:.04em}
@media print{body{margin:0;max-width:none}h2{page-break-after:avoid}tr{page-break-inside:avoid}}
"""


def to_html(c: dict, generated_at: str) -> str:
    body = md_to_html(to_markdown(c, generated_at))
    return (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{html.escape(c['title'])}</title>"
            f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><style>{HTML_CSS}</style></head>"
            f"<body><div class=\"brand\">SENTINELX AI · Detect. Investigate. Understand.</div>{body}</body></html>")


def to_pdf(c: dict, generated_at: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm, title=c["title"], author="SentinelX AI")
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("s", parent=body, fontSize=7.5, leading=9.5)
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontSize=16, textColor=colors.HexColor("#1f3a5f"))
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=12, textColor=colors.HexColor("#1f3a5f"), spaceBefore=10)
    esc = lambda t: html.escape(str(t if t is not None else "—"))  # noqa: E731
    story = [Paragraph("SENTINELX AI", small), Paragraph(esc(c["title"]), h1),
             Paragraph(f"Generated {esc(generated_at)} by {esc(c['generated_by'])} · Workspace: {esc(c['workspace'])}", small)]
    if c.get("synthetic_data"):
        story.append(Paragraph(f"<b>Note:</b> {esc(SYNTHETIC_NOTE)}", body))
    i = c["incident"]
    meta = [["Incident", i["number"]], ["Title", i["title"]], ["Status", i["status"]], ["Severity", i["severity"].upper()],
            ["Confidence", f"{i['confidence']:.2f}"], ["Risk score", f"{i['risk_score']}/100 ({i['risk_band']})"],
            ["First seen", _ts(i["first_seen"])], ["Last seen", _ts(i["last_seen"])], ["Assigned to", i["assigned_to"] or "—"]]
    tstyle = TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c8d0da")),
                         ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f4f8")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                         ("FONTSIZE", (0, 0), (-1, -1), 8)])
    story += [Spacer(1, 6), Table([[Paragraph(esc(a), body), Paragraph(esc(b), body)] for a, b in meta],
                                  colWidths=[35 * mm, 140 * mm], style=tstyle)]
    story += [Paragraph("Summary", h2), Paragraph(esc(c["summary"]), body),
              Paragraph(f"<b>Correlation:</b> {esc(c['correlation_reason'])}", body)]
    if c.get("ai_summary"):
        a = c["ai_summary"]
        label = f"LIVE AI ({a['provider']} / {a['model']})" if a["mode"] == "LIVE" else "DEMO AI / LOCAL ANALYSIS (no language model)"
        story.append(Paragraph(f"AI summary — {esc(label)}", h2))
        for line in a["markdown"].split("\n"):
            if line.strip():
                text = esc(line.strip().lstrip("- ").replace("**", ""))
                story.append(Paragraph(("• " if line.strip().startswith("- ") else "") + text, body))
    story.append(Paragraph("Detections", h2))
    rows = [[Paragraph(f"<b>{esc(d['rule_key'])}</b><br/>{esc(d['severity'].upper())}", small),
             Paragraph(f"<b>{esc(d['title'])}</b><br/>{esc(d.get('explanation') or '')}", small)] for d in c["detections"]]
    if rows:
        story.append(Table(rows, colWidths=[22 * mm, 153 * mm], style=tstyle))
    story.append(Paragraph("MITRE ATT&amp;CK techniques", h2))
    trows = [[Paragraph(esc(t["id"]), small), Paragraph(f"<b>{esc(t['name'])}</b> ({esc(t['tactic'])}) "
                                                       f"{esc(t.get('reason') or '')}", small)] for t in c["techniques"]]
    if trows:
        story.append(Table(trows, colWidths=[22 * mm, 153 * mm], style=tstyle))
    r = c["risk"]
    story += [Paragraph(f"SentinelX Risk Score — {r['score']}/100 ({esc(r['band'])})", h2), Paragraph(esc(r["disclaimer"]), small)]
    story.append(Table([[Paragraph(esc(f["factor"]), small), Paragraph(f"{f['points']}/{f['max']}", small),
                         Paragraph(esc(f["detail"]), small)] for f in r["factors"]],
                       colWidths=[45 * mm, 18 * mm, 112 * mm], style=tstyle))
    aa = c["affected_assets"]
    story += [Paragraph("Affected assets", h2),
              Paragraph(f"<b>Users:</b> {esc(', '.join(aa['users']) or '—')}<br/><b>Hosts:</b> "
                        f"{esc(', '.join(h['hostname'] + ' (' + h['criticality'] + ')' for h in aa['hosts']) or '—')}<br/>"
                        f"<b>Source IPs:</b> {esc(', '.join(aa['source_ips']) or '—')}<br/><b>External destinations:</b> "
                        f"{esc(', '.join(aa['destination_ips']) or '—')}", body)]
    story.append(Paragraph("Recommendations", h2))
    for n, rec in enumerate(c["recommendations"], 1):
        story.append(Paragraph(f"{n}. {esc(rec)}", body))
    if c["timeline"]:
        story += [PageBreak(), Paragraph("Timeline (evidence events)", h2)]
        tl = [[Paragraph(h, small) for h in ("Time (UTC)", "Event", "Type/Action", "User / Host", "Detail")]]
        for e in c["timeline"]:
            tl.append([Paragraph(esc(_ts(e["timestamp"])), small), Paragraph(esc(e["event_uid"]), small),
                       Paragraph(esc(f"{e['event_type']}/{e['action'] or ''} {e['status'] or ''}"), small),
                       Paragraph(esc(f"{e['user'] or ''} / {e['host'] or ''}"), small),
                       Paragraph(esc(e["detail"][:160]), small)])
        story.append(Table(tl, colWidths=[30 * mm, 26 * mm, 30 * mm, 34 * mm, 55 * mm], style=tstyle, repeatRows=1))
    doc.build(story)
    return buf.getvalue()
