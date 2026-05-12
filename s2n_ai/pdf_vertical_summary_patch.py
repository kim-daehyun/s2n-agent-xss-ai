from __future__ import annotations

def install_vertical_summary_patch(namespace: dict) -> None:
    """
    Patch ReportLab Table/LongTable so the S2N All Findings Summary wide table
    is rendered as a vertical key-value finding card.

    This patches both:
    - pdf_generator module namespace: Table / LongTable
    - reportlab.platypus.Table / LongTable

    Therefore it also catches local imports like:
        from reportlab.platypus import Table
    executed after this patch is installed.
    """
    try:
        import reportlab.platypus as platypus
        from reportlab.lib import colors
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import Paragraph, TableStyle
        from xml.sax.saxutils import escape as xml_escape
    except Exception as exc:
        print(f"[WARN] vertical summary patch import failed: {exc}")
        return

    original_table = getattr(platypus, "_s2n_original_table_v6", None)
    if original_table is None:
        original_table = platypus.Table
        setattr(platypus, "_s2n_original_table_v6", original_table)

    original_longtable = getattr(platypus, "_s2n_original_longtable_v6", None)
    if original_longtable is None:
        original_longtable = getattr(platypus, "LongTable", original_table)
        setattr(platypus, "_s2n_original_longtable_v6", original_longtable)

    def plain(value) -> str:
        if value is None:
            return "-"
        try:
            if hasattr(value, "getPlainText"):
                return str(value.getPlainText())
        except Exception:
            pass
        try:
            if hasattr(value, "text"):
                return str(value.text)
        except Exception:
            pass
        return str(value)

    def break_token(token: str, size: int = 18) -> str:
        if len(token) <= size:
            return token
        return "<br/>".join(token[i:i + size] for i in range(0, len(token), size))

    def wrap_value(value) -> str:
        text = xml_escape(plain(value))
        text = text.replace(chr(13), "")
        text = text.replace(chr(10), "<br/>")

        separators = [
            "&amp;", "&lt;", "&gt;", "%", "?", "=", "/", ".", "_", "-", ":",
            ";", "(", ")", "[", "]", "{", "}", ",", "'", "`", chr(34)
        ]
        for sep in separators:
            text = text.replace(sep, sep + "<br/>")

        return "<br/>".join(break_token(part) for part in text.split("<br/>"))

    def para(value, *, bold: bool = False, code: bool = False, size: float | None = None):
        font_name = "Courier" if code else ("Helvetica-Bold" if bold else "Helvetica")
        if size is None:
            size = 6.8 if code else 7.2

        return Paragraph(
            wrap_value(value),
            ParagraphStyle(
                name="S2NVerticalSummaryCellV6",
                fontName=font_name,
                fontSize=size,
                leading=size + 1.8,
                wordWrap="CJK",
                splitLongWords=True,
                spaceBefore=0,
                spaceAfter=0,
            ),
        )

    def headers(data) -> list[str]:
        try:
            return [plain(c).strip().lower().replace(chr(10), " ") for c in data[0]]
        except Exception:
            return []

    def is_finding_summary_table(data) -> bool:
        h = headers(data)
        hs = set(h)
        return (
            "id" in hs
            and "payload" in hs
            and "verification" in hs
            and ("param" in hs or "parameter" in hs)
            and ("severity" in hs or "confidence" in hs)
            and ("reflected" in hs or "server reflected" in hs)
        )

    def row_map(h: list[str], row) -> dict:
        values = [plain(c) for c in row]
        return {key: values[i] if i < len(values) else "-" for i, key in enumerate(h)}

    def yes_no(value) -> str:
        low = plain(value).strip().lower()
        if low in {"true", "1", "yes", "y"}:
            return "Yes"
        if low in {"false", "0", "no", "n"}:
            return "No"
        return plain(value)

    def human_verification(value) -> str:
        raw = plain(value)
        low = raw.lower()
        if "browser_dialog" in low or "dialog" in low:
            return "Browser alert/dialog observed"
        if "payload_reflected" in low:
            return "Payload reflected in HTTP response"
        if "direct_url_payload" in low:
            return "Payload reflected in direct URL response"
        if "reflected" in low:
            return "Payload reflected"
        return raw or "-"

    def is_browser_xss(item: dict) -> bool:
        blob = " ".join([
            plain(item.get("payload", "")),
            plain(item.get("verification", "")),
            plain(item.get("xss type", "")),
            plain(item.get("detection type", "")),
            plain(item.get("discovery mode", "")),
        ]).lower()

        return (
            "browser_dialog" in blob
            or "browser" in blob
            or "dom" in blob
            or "javascript:alert" in blob
            or "<iframe" in blob
        )

    def vertical_table(data, base_table_cls):
        h = headers(data)
        rows = []
        title_rows = []

        for idx, row in enumerate(data[1:], start=1):
            item = row_map(h, row)
            browser_ok = is_browser_xss(item)

            detection_type = "DOM/browser-executed XSS" if browser_ok else "Reflected XSS"
            browser_confirmed = "Yes" if browser_ok else "Not confirmed by browser probe"
            reflected_value = item.get("reflected", item.get("server reflected", "-"))
            server_reflected = yes_no(reflected_value)

            if browser_ok:
                interpretation = (
                    "Browser execution evidence was observed. Server Reflected=No can still be valid "
                    "for DOM XSS because the vulnerable behavior is confirmed in the browser/DOM."
                )
            else:
                interpretation = "The payload was confirmed through HTTP reflection evidence."

            title_rows.append(len(rows))
            rows.append([para(f"Finding #{idx}", bold=True, size=8.4), para("", size=8.4)])

            pairs = [
                ("ID", item.get("id", "-"), False),
                ("Severity", item.get("severity", "-"), False),
                ("Confidence", item.get("confidence", "-"), False),
                ("Detection Type", detection_type, False),
                ("Target Path", item.get("target path", item.get("path", "-")), True),
                ("Parameter", item.get("param", item.get("parameter", "-")), False),
                ("Payload", item.get("payload", "-"), True),
                ("Verification", human_verification(item.get("verification", "-")), False),
                ("Browser Execution Confirmed", browser_confirmed, False),
                ("Server Reflected", server_reflected, False),
                ("Interpretation", interpretation, False),
            ]

            for label, value, is_code in pairs:
                rows.append([para(label, bold=True), para(value, code=is_code)])

        table = base_table_cls(rows, colWidths=[135, 360], hAlign="LEFT", repeatRows=0)
        style_commands = [
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#C9CED6")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EEF1F5")),
        ]

        for r in title_rows:
            style_commands.append(("SPAN", (0, r), (1, r)))
            style_commands.append(("BACKGROUND", (0, r), (1, r), colors.HexColor("#DDE3EA")))

        table.setStyle(TableStyle(style_commands))
        return table

    def table_wrapper(data, *args, **kwargs):
        try:
            if is_finding_summary_table(data):
                print("[PDF] vertical finding summary v6 applied")
                return vertical_table(data, original_table)
        except Exception as exc:
            print(f"[WARN] vertical summary v6 fallback: {exc}")
        return original_table(data, *args, **kwargs)

    def longtable_wrapper(data, *args, **kwargs):
        try:
            if is_finding_summary_table(data):
                print("[PDF] vertical finding summary v6 applied to LongTable")
                return vertical_table(data, original_table)
        except Exception as exc:
            print(f"[WARN] vertical LongTable v6 fallback: {exc}")
        return original_longtable(data, *args, **kwargs)

    namespace["Table"] = table_wrapper
    namespace["LongTable"] = longtable_wrapper
    platypus.Table = table_wrapper
    platypus.LongTable = longtable_wrapper

    print("[PDF] vertical finding summary patch v6 installed")
