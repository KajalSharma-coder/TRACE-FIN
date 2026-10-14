"""
TRACE//FIN — PDF & DOCX Document Extraction Module (Phase 5)
Provides memory-safe, bounded, format-specific text extraction for PDF and DOCX files
with zip-bomb prevention, password/encryption detection, and structural integrity checks.
Uploaded files are processed in volatile memory and never persisted to disk.
"""

import io
import logging
import zipfile
from typing import Any, Dict, List, Optional

logger = logging.getLogger("tracefin.docs")

# Maximum upload constraints
MAX_FILE_SIZE_MB = 10
MAX_PDF_PAGES = 30
MAX_EXTRACTED_CHARS = 200_000  # ~40,000 words limit to prevent memory exhaustion
MAX_DOCX_PARAGRAPHS = 2_000
MAX_DOCX_TABLE_ROWS = 1_000
MAX_UNCOMPRESSED_RATIO = 100  # ZIP bomb threshold ratio


# ── PDF Extraction ─────────────────────────────────────────────────────

def extract_pdf_text(uploaded_file, max_pages: int = MAX_PDF_PAGES) -> Dict[str, Any]:
    """
    Extract text page-by-page from a PDF file using pypdf.
    Validates PDF magic bytes, handles passwords/encryption, and bounds page count.
    """
    res = {
        "valid": False,
        "text": "",
        "source_type": "PDF Document",
        "metadata": {},
        "warnings": [],
        "error": None,
    }

    if uploaded_file is None:
        res["error"] = "No file uploaded."
        return res

    try:
        data = uploaded_file.read()
        if hasattr(uploaded_file, "seek"):
            uploaded_file.seek(0)
    except Exception as exc:
        res["error"] = f"Failed to read file: {exc}"
        return res

    if len(data) == 0:
        res["error"] = "Uploaded PDF file is empty (0 bytes)."
        return res

    size_mb = len(data) / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        res["error"] = f"PDF file size ({size_mb:.1f} MB) exceeds maximum allowed limit ({MAX_FILE_SIZE_MB} MB)."
        return res

    # Verify PDF magic header bytes
    if not data.startswith(b"%PDF-"):
        res["error"] = "Invalid PDF signature: File does not start with '%PDF-' header."
        return res

    try:
        from pypdf import PdfReader
        from pypdf.errors import EmptyFileError, FileNotDecryptedError, PdfReadError

        stream = io.BytesIO(data)
        reader = PdfReader(stream)

        # Check if encrypted/password protected
        if reader.is_encrypted:
            # Try empty password
            try:
                decrypted = reader.decrypt("")
                if decrypted == 0:
                    res["error"] = "PDF document is encrypted / password-protected. Cannot extract text without password."
                    return res
            except Exception:
                res["error"] = "PDF document is encrypted / password-protected."
                return res

        total_pages = len(reader.pages)
        res["metadata"] = {
            "total_pages": total_pages,
            "size_kb": round(len(data) / 1024, 1),
            "encrypted": reader.is_encrypted,
        }

        # Check document information if available
        if reader.metadata:
            meta = reader.metadata
            if meta.title:
                res["metadata"]["title"] = str(meta.title)[:100]
            if meta.author:
                res["metadata"]["author"] = str(meta.author)[:100]

        pages_to_extract = min(total_pages, max_pages)
        if total_pages > max_pages:
            res["warnings"].append(
                f"Document has {total_pages} pages; extraction bounded to first {max_pages} pages."
            )

        extracted_pages = []
        total_chars = 0

        for i in range(pages_to_extract):
            page = reader.pages[i]
            page_text = page.extract_text() or ""
            clean_page = page_text.strip()
            if clean_page:
                extracted_pages.append(clean_page)
                total_chars += len(clean_page)
                if total_chars > MAX_EXTRACTED_CHARS:
                    res["warnings"].append(f"Reached maximum text limit ({MAX_EXTRACTED_CHARS:,} characters).")
                    break

        combined_text = "\n\n".join(extracted_pages).strip()

        if not combined_text:
            res["valid"] = True
            res["text"] = ""
            res["warnings"].append(
                "No extractable text found in PDF. This document may be a scanned image or raster graphic (OCR required)."
            )
            return res

        res["valid"] = True
        res["text"] = combined_text
        res["metadata"]["pages_extracted"] = len(extracted_pages)
        res["metadata"]["characters_extracted"] = len(combined_text)
        return res

    except Exception as exc:
        res["error"] = f"PDF parsing error: {exc}"
        return res


# ── DOCX Extraction ────────────────────────────────────────────────────

def extract_docx_text(uploaded_file) -> Dict[str, Any]:
    """
    Extract text safely from a Microsoft Word (.docx) document using python-docx.
    Includes ZIP bomb decompression ratio checks and extracts paragraphs and tables.
    """
    res = {
        "valid": False,
        "text": "",
        "source_type": "DOCX Document",
        "metadata": {},
        "warnings": [],
        "error": None,
    }

    if uploaded_file is None:
        res["error"] = "No file uploaded."
        return res

    try:
        data = uploaded_file.read()
        if hasattr(uploaded_file, "seek"):
            uploaded_file.seek(0)
    except Exception as exc:
        res["error"] = f"Failed to read file: {exc}"
        return res

    if len(data) == 0:
        res["error"] = "Uploaded DOCX file is empty (0 bytes)."
        return res

    size_mb = len(data) / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        res["error"] = f"DOCX file size ({size_mb:.1f} MB) exceeds maximum allowed limit ({MAX_FILE_SIZE_MB} MB)."
        return res

    # Verify ZIP magic bytes (DOCX is an OpenXML ZIP archive)
    if not data.startswith(b"PK\x03\x04"):
        res["error"] = "Invalid DOCX format: Missing ZIP container magic bytes (PK\\x03\\x04)."
        return res

    # ZIP bomb / decompression bomb protection
    try:
        stream = io.BytesIO(data)
        with zipfile.ZipFile(stream, "r") as zf:
            infolist = zf.infolist()
            total_uncompressed = sum(info.file_size for info in infolist)
            compressed_size = len(data)

            if compressed_size > 0 and (total_uncompressed / compressed_size) > MAX_UNCOMPRESSED_RATIO:
                res["error"] = "Suspicious compression ratio detected (potential ZIP bomb attack). Extraction aborted."
                return res

            # Verify it's actually a Word document (must contain word/document.xml or [Content_Types].xml)
            names = set(zf.namelist())
            if not ("word/document.xml" in names or "[Content_Types].xml" in names):
                res["error"] = "ZIP archive is not a valid OpenXML Word document (missing 'word/document.xml')."
                return res
    except zipfile.BadZipFile:
        res["error"] = "Corrupted or malformed DOCX archive (BadZipFile)."
        return res
    except Exception as exc:
        res["error"] = f"Archive validation error: {exc}"
        return res

    # Extract content using python-docx
    try:
        import docx

        stream.seek(0)
        doc = docx.Document(stream)

        paragraphs_text = []
        para_count = 0
        total_chars = 0

        # Extract paragraphs
        for p in doc.paragraphs:
            txt = p.text.strip()
            if txt:
                paragraphs_text.append(txt)
                total_chars += len(txt)
                para_count += 1
                if para_count >= MAX_DOCX_PARAGRAPHS or total_chars >= MAX_EXTRACTED_CHARS:
                    res["warnings"].append("Reached maximum paragraph/character limit during extraction.")
                    break

        # Extract tables if limits not exceeded
        table_rows_extracted = 0
        if total_chars < MAX_EXTRACTED_CHARS:
            for table in doc.tables:
                for row in table.rows:
                    row_cells = [cell.text.strip() for cell in row.cells if cell.text.strip()]
                    if row_cells:
                        row_line = " | ".join(row_cells)
                        paragraphs_text.append(row_line)
                        total_chars += len(row_line)
                        table_rows_extracted += 1
                        if table_rows_extracted >= MAX_DOCX_TABLE_ROWS or total_chars >= MAX_EXTRACTED_CHARS:
                            break

        combined_text = "\n\n".join(paragraphs_text).strip()

        res["valid"] = True
        res["text"] = combined_text
        res["metadata"] = {
            "size_kb": round(len(data) / 1024, 1),
            "paragraphs_extracted": para_count,
            "table_rows_extracted": table_rows_extracted,
            "characters_extracted": len(combined_text),
        }

        if not combined_text:
            res["warnings"].append("DOCX document contains no readable text or paragraphs.")

        return res

    except Exception as exc:
        res["error"] = f"DOCX document parsing error: {exc}"
        return res


# ── Unified Document Router ────────────────────────────────────────────

def extract_document_text(uploaded_file) -> Dict[str, Any]:
    """
    Route an uploaded document to either PDF or DOCX extractor based on file name & signature.
    """
    if uploaded_file is None:
        return {"valid": False, "text": "", "error": "No file uploaded.", "source_type": "Unknown"}

    filename = getattr(uploaded_file, "name", "").lower()

    if filename.endswith(".pdf"):
        return extract_pdf_text(uploaded_file)
    elif filename.endswith(".docx"):
        return extract_docx_text(uploaded_file)
    else:
        return {
            "valid": False,
            "text": "",
            "source_type": "Unsupported Document",
            "error": f"Unsupported file extension for '{filename}'. Only .pdf and .docx are supported.",
        }
