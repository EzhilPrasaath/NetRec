from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEV_COL = {"CRITICAL": "#b91c1c", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#2563eb", "UNKNOWN": "#6b7280"}
INK, TEAL = colors.HexColor("#14202b"), colors.HexColor("#0e7c86")
PER_SERVICE_CAP = 10


def e(v):
    return escape(str(v)) if v not in (None, "") else "-"


def _styles():
    ss = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=ss["Title"], textColor=INK, fontSize=24, alignment=0, spaceAfter=2),
        "sub": ParagraphStyle("s", parent=ss["Normal"], textColor=colors.grey, fontSize=10),
        "h1": ParagraphStyle("h1", parent=ss["Heading1"], textColor=TEAL, fontSize=15, spaceBefore=10),
        "h2": ParagraphStyle("h2", parent=ss["Heading2"], textColor=INK, fontSize=12, spaceBefore=8),
        "n": ParagraphStyle("n", parent=ss["Normal"], fontSize=9, leading=12),
        "c": ParagraphStyle("c", parent=ss["Normal"], fontSize=7.5, leading=9.5),
        "ch": ParagraphStyle("ch", parent=ss["Normal"], fontSize=8, leading=10, textColor=colors.white),
    }


def _table(rows, widths, S, header=True):
    data = [[c if not isinstance(c, str) else Paragraph(c, S["ch" if header and i == 0 else "c"]) for c in r]
            for i, r in enumerate(rows)]
    t = Table(data, colWidths=[w * mm for w in widths], repeatRows=1 if header else 0)
    st = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
          ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")])]
    if header:
        st.append(("BACKGROUND", (0, 0), (-1, 0), INK))
    t.setStyle(TableStyle(st))
    return t


def _pie(sev):
    items = [(k, sev.get(k, 0)) for k in SEV_ORDER if sev.get(k, 0)]
    if not items:
        return None
    d = Drawing(180 * mm, 55 * mm)
    p = Pie()
    p.x, p.y, p.width, p.height = 60 * mm, 4 * mm, 46 * mm, 46 * mm
    p.data = [v for _, v in items]
    p.labels = [f"{k.title()} ({v})" for k, v in items]
    p.sideLabels = 1
    p.slices.strokeWidth = 0.5
    p.slices.fontSize = 8
    for i, (k, _) in enumerate(items):
        p.slices[i].fillColor = colors.HexColor(SEV_COL[k])
    d.add(p)
    return d


def _bars(items):
    if not items:
        return None
    d = Drawing(180 * mm, 55 * mm)
    b = VerticalBarChart()
    b.x, b.y, b.width, b.height = 12 * mm, 10 * mm, 160 * mm, 38 * mm
    b.data = [[i["count"] for i in items]]
    b.categoryAxis.categoryNames = [i["label"] for i in items]
    b.categoryAxis.labels.fontSize = 7
    b.valueAxis.valueMin = 0
    b.valueAxis.valueStep = max(1, max(i["count"] for i in items) // 4)
    b.valueAxis.labels.fontSize = 7
    b.bars[0].fillColor = TEAL
    d.add(b)
    return d


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)
    canvas.drawString(15 * mm, 9 * mm, "NetRec | Confidential | For authorised security assessment only")
    canvas.drawRightString(195 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "-"


def build_pdf(scan, username):
    S, res = _styles(), scan.result
    sm, hosts = res["summary"], res["hosts"]
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=15 * mm, bottomMargin=16 * mm, title=f"NetRec report #{scan.id}")
    st = [Paragraph("NetRec", S["title"]), Paragraph("Network exposure and vulnerability report", S["sub"]), Spacer(1, 8)]
    meta = [["Target", e(scan.target)], ["Profile", e(scan.profile.title())],
            ["Ports", e(scan.ports or "profile default")], ["Time limit", f"{scan.timeout_min} min"],
            ["Started", _fmt(scan.started_at)], ["Finished", _fmt(scan.finished_at)],
            ["Run by", e(username)], ["Hosts up", f'{sm["hosts_up"]} of {res["stats"]["total"]} scanned']]
    st.append(_table(meta, [30, 150], S, header=False))
    if res["stats"].get("timed_out"):
        st.append(Paragraph("<b>Note:</b> the time limit was reached. Results may be incomplete.", S["n"]))
    if sm.get("cve_partial"):
        st.append(Paragraph("<b>Note:</b> the CVE lookup time budget was reached. Some services were not checked.", S["n"]))

    st.append(Paragraph("Executive summary", S["h1"]))
    st.append(_table([["Hosts up", "Open ports", "CVE findings", "Critical", "High", "Known exploited"],
                      [str(sm["hosts_up"]), str(sm["open_ports"]), str(sm["cve_findings"]),
                       str(sm["severity"]["CRITICAL"]), str(sm["severity"]["HIGH"]), str(sm["kev"])]],
                     [30, 30, 30, 30, 30, 30], S))
    st.append(Spacer(1, 6))
    for title, chart in (("Findings by severity", _pie(sm["severity"])), ("Most common open ports", _bars(sm["top_ports"]))):
        if chart:
            st += [Paragraph(title, S["h2"]), chart]
    st.append(Paragraph(
        "CVE findings are inferred from detected service versions (CPE matching against the NVD). They indicate "
        "<b>potential exposure</b>, not confirmed exploitability. Distribution packages often back-port fixes without "
        f"changing version strings. Findings marked * are low-confidence keyword matches and are excluded from the counts above.",
        S["n"]))

    st.append(Paragraph("Host overview", S["h1"]))
    rows = [["IP", "Hostname", "OS (accuracy)", "Open ports"]]
    for h in hosts:
        os_txt = f'{e(h["os"])} ({h["os_accuracy"]}%)' if h["os"] else "-"
        rows.append([e(h["ip"]), e(h["hostname"]), os_txt, str(len(h["ports"]))])
    st.append(_table(rows, [38, 55, 65, 22], S))

    for h in hosts:
        st.append(PageBreak())
        st.append(Paragraph(f'Host {e(h["ip"])}' + (f' ({e(h["hostname"])})' if h["hostname"] else ""), S["h1"]))
        st.append(Paragraph(f'OS: {e(h["os"])} | MAC: {e(h["mac"])} {e(h["vendor"])} | Closed/filtered ports: {h["not_open"]}', S["n"]))
        if h["ports"]:
            rows = [["Port", "Service", "Product / version", "CVEs"]]
            for p in h["ports"]:
                prod = " ".join(x for x in (p["product"], p["version"], p["extra"]) if x)
                rows.append([f'{p["port"]}/{p["proto"]}', e(p["service"]), e(prod), str(p["cve_total"] if p["cves"] else 0)])
            st += [Paragraph("Open ports", S["h2"]), _table(rows, [22, 30, 108, 20], S)]
        rows = [["CVE", "CVSS", "Severity", "Port", "Summary"]]
        more = 0
        for p in h["ports"]:
            star = "*" if p["cve_confidence"] == "low" else ""
            for c in p["cves"][:PER_SERVICE_CAP]:
                col = SEV_COL.get(c["severity"], SEV_COL["UNKNOWN"])
                rows.append([f'{e(c["id"])}{star}', e(c["score"]), f'<font color="{col}"><b>{e(c["severity"])}</b></font>',
                             f'{p["port"]}/{p["proto"]}', e(c["summary"][:150])])
            more += max(0, p["cve_total"] - min(len(p["cves"]), PER_SERVICE_CAP)) if p["cves"] else 0
        if len(rows) > 1:
            st += [Paragraph("Potential vulnerabilities", S["h2"]), _table(rows, [28, 12, 20, 18, 102], S)]
            if more:
                st.append(Paragraph(f"{more} further CVEs not shown. Search the NVD for the affected product.", S["n"]))
        else:
            st.append(Paragraph("No CVEs correlated for this host's detected services.", S["n"]))
    doc.build(st, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
