"""Minimal XLSX writer using only the standard library.

Produces a valid single-sheet Office Open XML spreadsheet (inline strings,
numbers as numbers, bold header row with an autofilter). Enough for
"export this table to Excel" without pulling in openpyxl.
"""

from __future__ import annotations

import io
import re
import zipfile
from xml.sax.saxutils import escape


_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>"""

_ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""

_WORKBOOK = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="{name}" sheetId="1" r:id="rId1"/></sheets>
</workbook>"""

_WORKBOOK_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""

# Style 1 = bold (header row)
_STYLES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>
<fills count="1"><fill><patternFill patternType="none"/></fill></fills>
<borders count="1"><border/></borders>
<cellStyleXfs count="1"><xf/></cellStyleXfs>
<cellXfs count="2"><xf/><xf fontId="1" applyFont="1"/></cellXfs>
</styleSheet>"""

# Characters not allowed in XML 1.0
_ILLEGAL_XML = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ud800-\udfff￾￿]")


def _col_letter(idx: int) -> str:
    """0-based column index -> A, B, ..., Z, AA, ..."""
    letters = ""
    idx += 1
    while idx:
        idx, rem = divmod(idx - 1, 26)
        letters = chr(65 + rem) + letters
    return letters


def _cell_xml(col: int, row: int, value, style: int = 0) -> str:
    ref = f"{_col_letter(col)}{row}"
    s = f' s="{style}"' if style else ""
    if value is None or value == "":
        return f'<c r="{ref}"{s}/>'
    if isinstance(value, bool):
        return f'<c r="{ref}"{s} t="b"><v>{1 if value else 0}</v></c>'
    if isinstance(value, (int, float)):
        return f'<c r="{ref}"{s}><v>{value}</v></c>'
    text = _ILLEGAL_XML.sub("", str(value))
    if len(text) > 32000:  # Excel cell limit is 32767 chars
        text = text[:32000] + "…"
    return f'<c r="{ref}"{s} t="inlineStr"><is><t xml:space="preserve">{escape(text)}</t></is></c>'


def make_xlsx(headers: list, rows: list, sheet_name: str = "Export") -> bytes:
    """Build an xlsx file from a header row and a list of row lists."""
    sheet_name = re.sub(r"[\\/*?\[\]:]", " ", str(sheet_name))[:31] or "Export"

    body = []
    body.append("<row r=\"1\">" +
                "".join(_cell_xml(c, 1, h, style=1) for c, h in enumerate(headers)) +
                "</row>")
    for r_idx, row in enumerate(rows, start=2):
        body.append(f'<row r="{r_idx}">' +
                    "".join(_cell_xml(c, r_idx, v) for c, v in enumerate(row)) +
                    "</row>")

    last_col = _col_letter(max(len(headers) - 1, 0))
    dimension = f"A1:{last_col}{len(rows) + 1}"
    # Reasonable column widths derived from content (capped)
    widths = []
    for c, h in enumerate(headers):
        w = len(str(h))
        for row in rows[:200]:
            if c < len(row) and row[c] is not None:
                w = max(w, min(len(str(row[c])), 60))
        widths.append(
            f'<col min="{c+1}" max="{c+1}" width="{min(max(w + 2, 8), 62)}" customWidth="1"/>')

    sheet = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<dimension ref="{dimension}"/>'
        '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" '
        'activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
        f'<cols>{"".join(widths)}</cols>'
        f'<sheetData>{"".join(body)}</sheetData>'
        f'<autoFilter ref="{dimension}"/>'
        '</worksheet>'
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CONTENT_TYPES)
        zf.writestr("_rels/.rels", _ROOT_RELS)
        zf.writestr("xl/workbook.xml", _WORKBOOK.format(name=escape(sheet_name)))
        zf.writestr("xl/_rels/workbook.xml.rels", _WORKBOOK_RELS)
        zf.writestr("xl/styles.xml", _STYLES)
        zf.writestr("xl/worksheets/sheet1.xml", sheet)
    return buf.getvalue()
