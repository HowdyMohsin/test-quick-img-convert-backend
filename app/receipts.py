"""PDF receipts for Quick IMG Convert v5.

Receipt number: ``QIC-{YYYY}-{000001}``, sequential per year
(see ``app.billing.next_receipt_no``). A receipt is emailed on manual
approval (with the PDF attached) and downloadable from the payments
table / history endpoint.

Renderer preference: reportlab first, fpdf2 second, and a small
hand-written minimal-PDF writer as a last resort so receipts never fail
for lack of a library. Add ``reportlab`` to requirements (see
``api/requirements-payments.txt``).
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any, Optional

BRAND_NAME = "Quick IMG Convert"


def receipt_filename(receipt_no: str) -> str:
    return f"receipt-{receipt_no}.pdf"


def _lines(data: dict) -> list[str]:
    amount = data.get("amount_cents", 0) / 100.0
    display = data.get("display_text") or f"${amount:,.2f} USD"
    return [
        BRAND_NAME,
        "Payment receipt",
        "",
        f"Receipt: {data.get('receipt_no', '')}",
        f"Date: {data.get('date', '')}",
        f"Billed to: {data.get('customer_name') or data.get('email', '')}",
        f"Email: {data.get('email', '')}",
        "",
        f"Plan: {data.get('plan_name', '')} ({data.get('interval', '')})",
        f"Provider: {data.get('provider_label', '')}",
        f"Reference: {data.get('reference', '')}",
        f"Amount: {display}",
        "",
        "Thank you for supporting Quick IMG Convert.",
    ]


def _render_reportlab(lines: list[str]) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.setTitle("Payment receipt — Quick IMG Convert")
    y = 270 * mm
    for i, line in enumerate(lines):
        if i == 0:
            c.setFont("Helvetica-Bold", 16)
        elif i == 1:
            c.setFont("Helvetica-Bold", 12)
        else:
            c.setFont("Helvetica", 10)
        c.drawString(20 * mm, y, line[:120])
        y -= 7 * mm if i < 2 else 5 * mm
    c.showPage()
    c.save()
    return buf.getvalue()


def _render_fpdf2(lines: list[str]) -> bytes:
    from fpdf import FPDF
    pdf = FPDF()
    pdf.set_title("Payment receipt — Quick IMG Convert")
    pdf.add_page()
    for i, line in enumerate(lines):
        pdf.set_font("Helvetica", "B" if i < 2 else "", 16 if i == 0 else 11)
        pdf.cell(0, 8, line[:120], new_x="LMARGIN", new_y="NEXT")
    out = pdf.output()
    return bytes(out) if isinstance(out, (bytes, bytearray)) else out.encode("latin-1")


def _render_minimal_pdf(lines: list[str]) -> bytes:
    """Minimal valid PDF (single page, Helvetica) — last-resort renderer."""
    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    content = "\n".join(
        f"BT /F1 {16 if i == 0 else 11} Tf 56 {720 - i * 18} Td ({esc(l[:120])}) Tj ET"
        for i, l in enumerate(lines))
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n"
        + content.encode("latin-1", "replace") + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n").encode()
    return bytes(out)


def generate_receipt_pdf(data: dict) -> tuple[bytes, str]:
    """Return ``(pdf_bytes, renderer)`` where renderer is reportlab/fpdf2/minimal."""
    lines = _lines(data)
    try:
        return _render_reportlab(lines), "reportlab"
    except ImportError:
        pass
    try:
        return _render_fpdf2(lines), "fpdf2"
    except ImportError:
        pass
    return _render_minimal_pdf(lines), "minimal"


def receipt_data(*, receipt_no: str, plan_name: str, interval: str,
                 amount_cents: int, provider_label: str, reference: str,
                 email: str, customer_name: Optional[str] = None,
                 display_text: Optional[str] = None,
                 date: Optional[str] = None) -> dict:
    return {
        "receipt_no": receipt_no,
        "plan_name": plan_name,
        "interval": interval,
        "amount_cents": amount_cents,
        "provider_label": provider_label,
        "reference": reference,
        "email": email,
        "customer_name": customer_name,
        "display_text": display_text,
        "date": date or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }
