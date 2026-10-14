"""
TRACE//FIN — Unit Tests for Document Extraction Module (Phase 5)
Tests PDF and DOCX text extraction, corruption handling, zip bomb defense, and metadata extraction.
"""

import io
import os
import sys
import zipfile
import pytest

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.document_extractor import (
    extract_pdf_text,
    extract_docx_text,
    extract_document_text,
)


class MockUploadedDoc:
    """Mock Streamlit UploadedFile object for document tests."""
    def __init__(self, name: str, data: bytes):
        self.name = name
        self._io = io.BytesIO(data)
        self.size = len(data)

    def read(self, *args, **kwargs):
        return self._io.read(*args, **kwargs)

    def seek(self, *args, **kwargs):
        return self._io.seek(*args, **kwargs)


def _generate_valid_docx(paragraphs=None, table_data=None) -> bytes:
    """Dynamically generate valid DOCX bytes in memory."""
    import docx
    doc = docx.Document()
    if paragraphs:
        for p in paragraphs:
            doc.add_paragraph(p)
    if table_data:
        table = doc.add_table(rows=len(table_data), cols=len(table_data[0]))
        for r_idx, row in enumerate(table_data):
            for c_idx, val in enumerate(row):
                table.cell(r_idx, c_idx).text = str(val)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _generate_valid_pdf(text_content: str = "Urgent: Selling fully verified KYC bank account") -> bytes:
    """Dynamically generate valid PDF bytes in memory."""
    from pypdf import PdfWriter
    from pypdf.generic import Destination

    writer = PdfWriter()
    # Add a blank page with text annotation or basic text
    page = writer.add_blank_page(width=612, height=792)

    # Write to in-memory buffer
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


# ── 1. PDF Extraction Tests ───────────────────────────────────────────

def test_extract_pdf_empty_input():
    res = extract_pdf_text(None)
    assert res["valid"] is False
    assert "No file" in res["error"]

    mock_empty = MockUploadedDoc("empty.pdf", b"")
    res_empty = extract_pdf_text(mock_empty)
    assert res_empty["valid"] is False
    assert "empty" in res_empty["error"].lower()


def test_extract_pdf_invalid_header():
    mock_corrupt = MockUploadedDoc("corrupt.pdf", b"NOT_A_PDF_DOCUMENT_123456789")
    res = extract_pdf_text(mock_corrupt)
    assert res["valid"] is False
    assert "Invalid PDF signature" in res["error"]


def test_extract_pdf_scanned_blank_warning():
    # Valid PDF with no text elements
    pdf_bytes = _generate_valid_pdf("")
    mock_doc = MockUploadedDoc("scanned_poster.pdf", pdf_bytes)
    res = extract_pdf_text(mock_doc)
    assert res["valid"] is True
    assert res["text"] == ""
    assert any("scanned" in w.lower() or "no extractable text" in w.lower() for w in res["warnings"])


# ── 2. DOCX Extraction Tests ──────────────────────────────────────────

def test_extract_docx_valid():
    docx_bytes = _generate_valid_docx(
        paragraphs=[
            "Confidential Financial Memo",
            "Urgent: Sell your current account for 10k commission. Contact @seller",
        ],
        table_data=[
            ["Account Holder", "Bank", "IFSC"],
            ["Rohan Kumar", "HDFC", "HDFC0437589"],
        ]
    )
    mock_doc = MockUploadedDoc("memo.docx", docx_bytes)
    res = extract_docx_text(mock_doc)

    assert res["valid"] is True
    assert res["source_type"] == "DOCX Document"
    assert "Confidential Financial Memo" in res["text"]
    assert "Sell your current account" in res["text"]
    assert "Rohan Kumar" in res["text"]
    assert res["metadata"]["paragraphs_extracted"] >= 2
    assert res["metadata"]["table_rows_extracted"] >= 2


def test_extract_docx_empty_and_corrupt():
    assert extract_docx_text(None)["valid"] is False

    mock_empty = MockUploadedDoc("empty.docx", b"")
    assert extract_docx_text(mock_empty)["valid"] is False

    mock_bad_zip = MockUploadedDoc("corrupt.docx", b"PK\x03\x04INVALID_TRUNCATED_ZIP")
    res_bad = extract_docx_text(mock_bad_zip)
    assert res_bad["valid"] is False
    assert "Corrupted" in res_bad["error"] or "error" in res_bad["error"].lower()


def test_extract_docx_zip_bomb_detection():
    # Create an artificial archive where uncompressed >> compressed
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # 1 MB of zeroes compresses to a few hundred bytes
        zf.writestr("word/document.xml", b"0" * 1_000_000)
    data = buf.getvalue()

    mock_doc = MockUploadedDoc("bomb.docx", data)
    res = extract_docx_text(mock_doc)
    # Compression ratio of 1,000,000 / ~1000 is ~1000x, exceeding MAX_UNCOMPRESSED_RATIO
    assert res["valid"] is False
    assert "ZIP bomb" in res["error"] or "compression ratio" in res["error"].lower()


# ── 3. Unified Document Router ─────────────────────────────────────────

def test_extract_document_text_routing():
    docx_bytes = _generate_valid_docx(paragraphs=["Test document router"])
    mock_docx = MockUploadedDoc("sample.docx", docx_bytes)
    res_docx = extract_document_text(mock_docx)
    assert res_docx["source_type"] == "DOCX Document"
    assert "Test document router" in res_docx["text"]

    mock_unsupported = MockUploadedDoc("image.png", b"test")
    res_unsupported = extract_document_text(mock_unsupported)
    assert res_unsupported["valid"] is False
    assert "Unsupported file extension" in res_unsupported["error"]
