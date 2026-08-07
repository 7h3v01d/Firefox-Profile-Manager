# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright 2026 Leon Priest <https://github.com/7h3v01d>
"""Render USER_MANUAL.md to a printable PDF.

Deliberately a small purpose-built renderer rather than a general markdown
engine: the manual uses a known, fixed subset (headings, tables, fenced
code, lists, bold/inline code) and a narrow renderer is easier to predict
than configuring a general one.
"""

import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, KeepTogether, ListFlowable, ListItem,
    PageBreak, PageTemplate, Paragraph, Preformatted, Spacer, Table, TableStyle,
)

SRC = Path("USER_MANUAL.md")
OUT = Path("Firefox_Profile_Manager_User_Manual.pdf")

INK = colors.HexColor("#14181c")
MUTED = colors.HexColor("#5b666f")
ACCENT = colors.HexColor("#0f7d72")     # teal, darkened for paper contrast
WARN = colors.HexColor("#8a5a00")       # amber, darkened for paper contrast
RULE = colors.HexColor("#d4dade")
CODE_BG = colors.HexColor("#f2f5f6")
HEAD_BG = colors.HexColor("#e8eef0")

styles = getSampleStyleSheet()

# Helvetica has no glyph for U+26A0. The warning triangle is the marker the
# user actually sees in the app, so the manual should show the same symbol
# rather than a substitute. DejaVu Sans is used for that character only.
WARN_FONT = "Helvetica-Bold"
try:
    pdfmetrics.registerFont(
        TTFont("DejaVuSans", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"))
    WARN_FONT = "DejaVuSans"
except Exception:
    pass


def style(name, **kw):
    kw.setdefault("parent", styles["Normal"])
    return ParagraphStyle(name, **kw)


BODY = style("Body", fontName="Helvetica", fontSize=10, leading=15,
             textColor=INK, spaceAfter=7, alignment=TA_LEFT)
H1 = style("H1", fontName="Helvetica-Bold", fontSize=22, leading=27,
           textColor=INK, spaceBefore=0, spaceAfter=4)
H2 = style("H2", fontName="Helvetica-Bold", fontSize=15, leading=20,
           textColor=ACCENT, spaceBefore=18, spaceAfter=7)
H3 = style("H3", fontName="Helvetica-Bold", fontSize=11.5, leading=16,
           textColor=INK, spaceBefore=12, spaceAfter=5)
H4 = style("H4", fontName="Helvetica-BoldOblique", fontSize=10.5, leading=15,
           textColor=MUTED, spaceBefore=9, spaceAfter=4)
CODE = style("Code", fontName="Courier", fontSize=8.4, leading=11.6,
             textColor=INK, backColor=CODE_BG, borderPadding=7,
             spaceBefore=5, spaceAfter=9, leftIndent=2)
CELL = style("Cell", fontName="Helvetica", fontSize=9, leading=12.6,
             textColor=INK)
CELL_HEAD = style("CellHead", fontName="Helvetica-Bold", fontSize=9,
                  leading=12.6, textColor=INK)
BULLET = style("Bullet", parent=BODY, spaceAfter=3)
FOOTNOTE = style("Footnote", fontName="Helvetica-Oblique", fontSize=8.5,
                 leading=12, textColor=MUTED, spaceBefore=3)


def inline(text: str) -> str:
    """Convert the inline markdown subset to ReportLab markup."""
    text = (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    # `code`
    text = re.sub(r"`([^`]+)`",
                  r'<font face="Courier" size="9" color="#0f4f49">\1</font>',
                  text)
    # **bold**
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    # *italic*
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<i>\1</i>", text)
    # the warning glyph has no Helvetica coverage; render as a word
    warn = f'<font face="{WARN_FONT}" color="#8a5a00">\u26a0</font>'
    text = text.replace("\u26a0\ufe0f", warn).replace("\u26a0", warn)
    text = text.replace("\u2192", "&#8594;")
    return text


def split_row(line: str):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def build_table(rows):
    header, body = rows[0], rows[1:]
    data = [[Paragraph(inline(c), CELL_HEAD) for c in header]]
    data += [[Paragraph(inline(c), CELL) for c in r] for r in body]

    ncols = len(header)
    avail = 170 * mm
    if ncols == 2:
        widths = [avail * 0.38, avail * 0.62]
    elif ncols == 3:
        widths = [avail * 0.24, avail * 0.38, avail * 0.38]
    else:
        widths = [avail / ncols] * ncols

    t = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, ACCENT),
        ("GRID", (0, 0), (-1, -1), 0.3, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafcfc")]),
    ]))
    return t


def parse(md_text: str):
    story = []
    lines = md_text.split("\n")
    i = 0
    pending_bullets = []

    def flush_bullets():
        nonlocal pending_bullets
        if pending_bullets:
            story.append(ListFlowable(
                [ListItem(Paragraph(inline(b), BULLET), leftIndent=14)
                 for b in pending_bullets],
                bulletType="bullet", bulletFontSize=7, bulletOffsetY=-1,
                leftIndent=12, spaceAfter=8,
            ))
            pending_bullets = []

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # fenced code
        if stripped.startswith("```"):
            flush_bullets()
            i += 1
            block = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                block.append(lines[i])
                i += 1
            i += 1
            story.append(Preformatted("\n".join(block), CODE))
            continue

        # table
        if stripped.startswith("|") and i + 1 < len(lines) and \
                re.match(r"^\|[\s:|-]+\|$", lines[i + 1].strip()):
            flush_bullets()
            rows = [split_row(stripped)]
            i += 2
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(split_row(lines[i].strip()))
                i += 1
            story.append(Spacer(1, 2))
            story.append(build_table(rows))
            story.append(Spacer(1, 10))
            continue

        # horizontal rule
        if stripped in ("---", "***", "___"):
            flush_bullets()
            story.append(Spacer(1, 4))
            story.append(HRFlowable(width="100%", thickness=0.6, color=RULE,
                                    spaceBefore=2, spaceAfter=10))
            i += 1
            continue

        # headings
        m = re.match(r"^(#{1,4})\s+(.*)$", stripped)
        if m:
            flush_bullets()
            level, text = len(m.group(1)), m.group(2)
            if level == 1:
                story.append(Paragraph(inline(text), H1))
            elif level == 2:
                story.append(KeepTogether([Paragraph(inline(text), H2)]))
            elif level == 3:
                story.append(KeepTogether([Paragraph(inline(text), H3)]))
            else:
                story.append(Paragraph(inline(text), H4))
            i += 1
            continue

        # bullets (with continuation lines)
        m = re.match(r"^[-*]\s+(.*)$", stripped)
        if m:
            item = m.group(1)
            i += 1
            while i < len(lines):
                nxt = lines[i]
                if not nxt.strip():
                    break
                if re.match(r"^\s*([-*]\s+|\d+\.\s+|#{1,4}\s+|\|)", nxt) or \
                        nxt.strip().startswith("```") or \
                        nxt.strip() in ("---", "***", "___"):
                    break
                item += " " + nxt.strip()
                i += 1
            pending_bullets.append(item)
            continue

        # numbered list
        m = re.match(r"^(\d+)\.\s+(.*)$", stripped)
        if m:
            flush_bullets()
            items = []
            while i < len(lines):
                mm_ = re.match(r"^(\d+)\.\s+(.*)$", lines[i].strip())
                if not mm_:
                    # continuation line indented under the item
                    if items and lines[i].startswith("   ") and lines[i].strip():
                        items[-1] += " " + lines[i].strip()
                        i += 1
                        continue
                    break
                items.append(mm_.group(2))
                i += 1
            story.append(ListFlowable(
                [ListItem(Paragraph(inline(it), BULLET), leftIndent=16)
                 for it in items],
                bulletType="1", leftIndent=14, spaceAfter=8,
            ))
            continue

        # blank
        if not stripped:
            flush_bullets()
            i += 1
            continue

        # italic trailer lines
        if stripped.startswith("*") and stripped.endswith("*") and \
                not stripped.startswith("**"):
            flush_bullets()
            story.append(Paragraph(inline(stripped.strip("*")), FOOTNOTE))
            i += 1
            continue

        # ordinary paragraph: join wrapped source lines until a blank line or
        # the start of another block. Without this, every hard-wrapped line in
        # the markdown becomes its own spaced paragraph.
        flush_bullets()
        para = [stripped]
        i += 1
        while i < len(lines):
            nxt = lines[i]
            if not nxt.strip():
                break
            if re.match(r"^\s*([-*]\s+|\d+\.\s+|#{1,4}\s+|\|)", nxt) or \
                    nxt.strip().startswith("```") or \
                    nxt.strip() in ("---", "***", "___"):
                break
            para.append(nxt.strip())
            i += 1
        story.append(Paragraph(inline(" ".join(para)), BODY))
        continue

    flush_bullets()
    return story


def decorate(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    if doc.page > 1:
        canvas.drawString(20 * mm, h - 12 * mm, "Firefox Profile Manager 1.0.0")
        canvas.setStrokeColor(RULE)
        canvas.setLineWidth(0.4)
        canvas.line(20 * mm, h - 14 * mm, w - 20 * mm, h - 14 * mm)
    canvas.drawCentredString(w / 2, 11 * mm, str(doc.page))
    canvas.drawRightString(w - 20 * mm, 11 * mm, "User Manual")
    canvas.restoreState()


def main():
    text = SRC.read_text(encoding="utf-8")
    doc = BaseDocTemplate(
        str(OUT), pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=20 * mm, bottomMargin=18 * mm,
        title="Firefox Profile Manager 1.0.0 - User Manual",
        author="Leon Priest",
        subject="Removing fake virus pop-up notifications from Firefox",
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin,
                  doc.width, doc.height, id="body")
    doc.addPageTemplates([PageTemplate(id="all", frames=[frame],
                                       onPage=decorate)])
    doc.build(parse(text))
    print(f"wrote {OUT} ({OUT.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
