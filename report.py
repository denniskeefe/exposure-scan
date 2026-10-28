"""Builds the fixed 10-page PDF report from a reviewed Run."""
from __future__ import annotations

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (KeepInFrame, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

from models import CATEGORIES, CATEGORY_LABELS, Run
from scoring import score as compute_score

NAVY = colors.HexColor("#14213d")
GREY = colors.HexColor("#5c6370")
LIGHT = colors.HexColor("#eef1f6")
BAND_COLOR = {"Low": "#2a9d8f", "Moderate": "#e9c46a", "High": "#f4a261", "Critical": "#d62828"}
SEV_LABEL = {1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
TOTAL_PAGES = 10

_ss = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=_ss["Heading1"], fontName="Helvetica-Bold", fontSize=20, textColor=NAVY, spaceAfter=10)
H2 = ParagraphStyle("H2", parent=_ss["Heading2"], fontName="Helvetica-Bold", fontSize=13, textColor=NAVY, spaceBefore=10, spaceAfter=4)
BODY = ParagraphStyle("Body", parent=_ss["BodyText"], fontName="Helvetica", fontSize=10, leading=14)
SMALL = ParagraphStyle("Small", parent=BODY, fontSize=8.5, leading=11)
CELL = ParagraphStyle("Cell", parent=BODY, fontSize=8.5, leading=11)
CELLB = ParagraphStyle("CellB", parent=CELL, fontName="Helvetica-Bold", textColor=colors.white)


def P(text, style=BODY):
    return Paragraph(text, style)


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def table(rows, widths, header=True):
    data = [[c if not isinstance(c, str) else P(esc(c), CELLB if (header and i == 0) else CELL)
             for c in r] for i, r in enumerate(rows)]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c9ced8")),
             ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), NAVY)]
        style += [("BACKGROUND", (0, i), (-1, i), LIGHT) for i in range(2, len(rows), 2)]
    t.setStyle(TableStyle(style))
    return t


def bar_chart(cats, bands, width):
    d = Drawing(width, 30 + 34 * len(cats))
    y = d.height - 30
    for c in CATEGORIES:
        d.add(String(0, y + 8, CATEGORY_LABELS[c], fontName="Helvetica", fontSize=9, fillColor=NAVY))
        d.add(Rect(0, y - 8, width - 60, 12, fillColor=LIGHT, strokeColor=None))
        d.add(Rect(0, y - 8, (width - 60) * cats[c] / 100, 12,
                   fillColor=colors.HexColor(BAND_COLOR[bands[c]]), strokeColor=None))
        d.add(String(width - 52, y - 6, f"{cats[c]}/100 {bands[c]}", fontName="Helvetica-Bold", fontSize=8, fillColor=NAVY))
        y -= 34
    return d


def sev_cell(n):
    return f"{n} - {SEV_LABEL[n]}"


def findings_table(fs, widths):
    rows = [["ID", "Finding", "Severity", "Recommended action"]]
    rows += [[f.id, f"{f.title}. {f.detail}", sev_cell(f.severity), f.recommendation] for f in fs]
    return table(rows, widths) if fs else P("No approved findings in this category.")


def build(run: Run, out_path: str) -> int:
    if any(f.status == "pending" for f in run.findings):
        raise ValueError("Report blocked: findings still pending analyst review")
    if not run.analyst:
        raise ValueError("Report blocked: analyst has not signed off")

    s = compute_score(run.findings)
    ok = [f for f in run.findings if f.status == "approved"]
    rejected = [f for f in run.findings if f.status == "rejected"]
    by_cat = {c: sorted([f for f in ok if f.category == c], key=lambda f: -f.severity) for c in CATEGORIES}
    sub = run.subject
    demo = run.mode == "demo"

    doc = SimpleDocTemplate(out_path, pagesize=letter, leftMargin=0.8 * inch, rightMargin=0.8 * inch,
                            topMargin=0.8 * inch, bottomMargin=0.8 * inch,
                            title=f"Digital Exposure Report - {sub.full_name}", author=run.analyst)
    W, H = doc.width, doc.height - 6
    top = sorted(ok, key=lambda f: -f.severity)

    pages = []

    # 1 Cover
    pages.append([
        Spacer(1, 1.6 * inch), P("DIGITAL EXPOSURE REPORT", ParagraphStyle("c", parent=H1, fontSize=30, leading=34)),
        P("Breach, data broker, social and search exposure", ParagraphStyle("c2", parent=BODY, fontSize=14, textColor=GREY)),
        Spacer(1, 0.5 * inch),
        table([["Prepared for", esc(sub.full_name)], ["Scan date", run.scanned_at],
               ["Analyst review", f"{run.analyst} ({run.reviewed_at})"],
               ["Overall risk", f"{s['overall']}/100 - {s['band']}"], ["Consent reference", sub.consent_ref]],
              [1.6 * inch, W - 1.6 * inch], header=False),
        Spacer(1, 0.4 * inch),
        P("<b>DEMONSTRATION DATA - all subjects, breaches and results are fictional.</b>" if demo else
          "Confidential. Prepared only for the named subject, who authorized this assessment.", SMALL)])

    # 2 Executive summary
    counts = {c: len(by_cat[c]) for c in CATEGORIES}
    worst = top[:3]
    pages.append([
        P("1. Executive summary", H1),
        P(f"Overall exposure for <b>{esc(sub.full_name)}</b> is rated <b>{s['band']}</b> "
          f"({s['overall']}/100). An automated scan produced {len(run.findings)} candidate findings; an analyst "
          f"approved {len(ok)} and rejected {len(rejected)} as false positives or not applicable."),
        Spacer(1, 8), bar_chart(s["categories"], s["category_bands"], W), Spacer(1, 6),
        P("Highest-priority findings", H2),
        table([["ID", "Finding", "Severity"]] + [[f.id, f.title, sev_cell(f.severity)] for f in worst],
              [0.7 * inch, W - 1.9 * inch, 1.2 * inch]) if worst else P("None."),
        P("What this means", H2),
        P(f"Approved findings by area: breaches {counts['breach']}, data brokers {counts['broker']}, "
          f"social and search {counts['social_search']}. Data broker listings and reused-password breaches "
          "drive most of the practical risk (stalking, identity theft, account takeover, targeted phishing). "
          "Section 7 sets out a 30/60/90-day plan.")])

    # 3 Scope & method
    pages.append([
        P("2. Scope, methodology and limitations", H1),
        P("Identifiers assessed", H2),
        table([["Type", "Values"], ["Name", esc(sub.full_name)], ["Emails", esc(", ".join(sub.emails) or "-")],
               ["Phones", esc(", ".join(sub.phones) or "-")], ["Usernames", esc(", ".join(sub.usernames) or "-")],
               ["Location", esc(f"{sub.city}, {sub.state}")]], [1.3 * inch, W - 1.3 * inch]),
        P("Method", H2),
        P("1) <b>Automated scan</b>: breach lookups for each email, a checklist of people-search sites, and "
          "web searches on name, email, phone and usernames. 2) <b>Analyst review</b>: every finding is approved, "
          "rejected or re-scored by a human before it can enter this report. 3) <b>Scoring</b>: approved findings "
          "are weighted by severity per category (breach 40%, brokers 30%, social/search 30%)."),
        P("Limitations", H2),
        P("Breach data covers only publicly reported incidents. People-search sites change layouts and block "
          "automated access, so broker results depend on analyst confirmation. Search engines return a "
          "sample of results, not everything that exists. The dark web and private databases are out of scope. "
          "Absence of a finding is not proof of absence of exposure.")])

    # 4 Breach overview
    breach = by_cat["breach"]
    pw = sum(1 for f in breach if "Passwords" in f.detail)
    pages.append([
        P("3. Breach exposure", H1),
        P(f"{len(breach)} breaches affect the assessed email addresses; {pw} included passwords. "
          "Credential reuse is the most common route from a breach to account takeover."),
        Spacer(1, 6), findings_table(breach, [0.55 * inch, 2.9 * inch, 0.9 * inch, W - 4.35 * inch])])

    # 5 Breach analysis
    classes = {}
    for f in breach:
        part = f.detail.split("Exposed:")[-1].strip().rstrip(".")
        for c in part.split(","):
            classes[c.strip()] = classes.get(c.strip(), 0) + 1
    pages.append([
        P("4. Breach analysis: what was exposed", H1),
        P("Data types exposed across breaches", H2),
        table([["Data type", "Breaches"]] + [[k, str(v)] for k, v in sorted(classes.items(), key=lambda kv: -kv[1])],
              [3 * inch, 1 * inch]) if classes else P("No breach data."),
        P("Interpretation", H2),
        P("Passwords and dates of birth enable account takeover and identity verification fraud. Addresses and "
          "phone numbers feed data brokers and make targeted phishing or SIM-swap attempts more convincing. "
          "Exposed email addresses alone are low risk but confirm the address is active and traded."),
        P("Immediate hygiene", H2),
        P("Use a password manager with unique passwords per site, enable app-based or hardware multi-factor "
          "authentication on email, banking and mobile carrier accounts, and add a carrier PIN.")])

    # 6 Brokers
    pages.append([
        P("5. Data broker exposure", H1),
        P(f"{len(by_cat['broker'])} confirmed listings on people-search sites. Brokers aggregate public records "
          "and purchased data, then resell it to anyone."),
        Spacer(1, 6), findings_table(by_cat["broker"], [0.55 * inch, 2.9 * inch, 0.9 * inch, W - 4.35 * inch])])

    # 7 Social & search
    pages.append([
        P("6. Social and search exposure", H1),
        P(f"{len(by_cat['social_search'])} results surfaced for the subject's identifiers. Severity rises when a "
          "result links several identifiers (name with email, phone or location)."),
        Spacer(1, 6), findings_table(by_cat["social_search"], [0.55 * inch, 2.9 * inch, 0.9 * inch, W - 4.35 * inch])])

    # 8 Risk register
    pages.append([
        P("Risk register (all approved findings)", H1),
        table([["ID", "Area", "Source", "Finding", "Sev"]] +
              [[f.id, CATEGORY_LABELS[f.category], f.source, f.title, str(f.severity)] for f in top],
              [0.6 * inch, 1.5 * inch, 1.3 * inch, W - 3.9 * inch, 0.5 * inch])])

    # 9 Plan
    def tier(lo, hi):
        return [f for f in top if lo <= f.severity <= hi]
    def plan_rows(fs):
        seen, rows = set(), []
        for f in fs:
            if f.recommendation not in seen:
                seen.add(f.recommendation)
                rows.append([f.id, f.recommendation])
        return rows
    plan = [P("7. Remediation plan", H1)]
    for label, fs in (("Days 0-30: critical and high", tier(4, 5)), ("Days 31-60: medium", tier(3, 3)),
                      ("Days 61-90: low and informational", tier(1, 2))):
        plan.append(P(label, H2))
        rows = plan_rows(fs)
        plan.append(table([["Ref", "Action"]] + rows, [0.7 * inch, W - 0.7 * inch]) if rows else P("Nothing in this tier."))
    plan.append(P("Ongoing: re-scan every 90 days; brokers frequently re-list removed records.", SMALL))
    pages.append(plan)

    # 10 Sign-off
    pages.append([
        P("Analyst sign-off and appendix", H1),
        P(f"Reviewed by <b>{esc(run.analyst)}</b> on {run.reviewed_at}. All {len(run.findings)} automated findings were "
          "individually dispositioned."),
        P("Rejected findings", H2),
        table([["ID", "Finding", "Analyst reason"]] + [[f.id, f.title, f.analyst_note or "-"] for f in rejected],
              [0.7 * inch, W * 0.5, W * 0.5 - 0.7 * inch]) if rejected else P("None."),
        P("Analyst notes on approved findings", H2),
        table([["ID", "Note"]] + [[f.id, f.analyst_note] for f in ok if f.analyst_note],
              [0.7 * inch, W - 0.7 * inch]) if any(f.analyst_note for f in ok) else P("None."),
        P("Data sources", H2),
        P("Have I Been Pwned (breaches); people-search sites checked by the analyst; Brave Search API (web and social). "
          "Scan notes: " + esc("; ".join(run.scan_notes) or "none") + ".", SMALL)])

    assert len(pages) == TOTAL_PAGES, len(pages)
    story = []
    for i, content in enumerate(pages):
        story.append(KeepInFrame(W, H, content, mode="shrink"))
        if i < len(pages) - 1:
            story.append(PageBreak())

    def footer(c, d):
        c.saveState()
        c.setFont("Helvetica", 8); c.setFillColor(GREY)
        c.drawString(d.leftMargin, 0.45 * inch, "Confidential - digital exposure report" + (" - DEMO DATA" if demo else ""))
        c.drawRightString(letter[0] - d.rightMargin, 0.45 * inch, f"Page {c.getPageNumber()} of {TOTAL_PAGES}")
        c.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return TOTAL_PAGES
