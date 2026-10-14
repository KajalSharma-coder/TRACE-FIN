"""
TRACE//FIN — OCR Engine Module (Phase 4)
Image validation and Tesseract OCR text extraction for advertisement screenshots.
Images are never persisted to disk or sent to external services.
"""

import io
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("tracefin.ocr")

# Maximum upload constraints
MAX_FILE_SIZE_MB = 10
MAX_DIMENSION = 8000
MIN_DIMENSION = 50
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
ALLOWED_MIME_PREFIXES = {"image/jpeg", "image/png", "image/webp"}


def is_tesseract_available() -> bool:
    """Check whether Tesseract OCR binary is installed and callable."""
    try:
        import pytesseract
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def validate_image(uploaded_file) -> Dict[str, Any]:
    """
    Validate an uploaded image file for type, size, and dimensions.

    Args:
        uploaded_file: A Streamlit UploadedFile or file-like object with
                       .name, .size, .read() attributes.

    Returns:
        dict with keys: valid, error, image, file_size_kb, dimensions
    """
    result = {
        "valid": False,
        "error": None,
        "image": None,
        "file_size_kb": 0.0,
        "dimensions": (0, 0),
    }

    if uploaded_file is None:
        result["error"] = "No file uploaded."
        return result

    # Check file size
    try:
        file_bytes = uploaded_file.read()
        uploaded_file.seek(0)  # Reset for potential re-read
        file_size_kb = len(file_bytes) / 1024
        result["file_size_kb"] = round(file_size_kb, 1)

        if len(file_bytes) == 0:
            result["error"] = "Uploaded file is empty (0 bytes)."
            return result

        max_bytes = MAX_FILE_SIZE_MB * 1024 * 1024
        if len(file_bytes) > max_bytes:
            result["error"] = f"File too large ({file_size_kb/1024:.1f} MB). Maximum: {MAX_FILE_SIZE_MB} MB."
            return result
    except Exception as exc:
        result["error"] = f"Cannot read uploaded file: {exc}"
        return result

    # Check extension
    filename = getattr(uploaded_file, "name", "") or ""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        result["error"] = (
            f"Unsupported file type '.{ext}'. "
            f"Accepted: {', '.join(sorted(ALLOWED_EXTENSIONS))}."
        )
        return result

    # Validate via PIL header (content-type check, not just extension)
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(file_bytes))
        img.verify()  # Verify integrity
        # Re-open after verify (verify closes the file)
        img = Image.open(io.BytesIO(file_bytes))
    except Exception as exc:
        result["error"] = f"Corrupt or unreadable image file: {exc}"
        return result

    # Check format
    fmt = (img.format or "").upper()
    valid_formats = {"JPEG", "PNG", "WEBP"}
    if fmt not in valid_formats:
        result["error"] = f"Image format '{fmt}' not supported. Accepted: JPEG, PNG, WEBP."
        return result

    # Check dimensions
    w, h = img.size
    result["dimensions"] = (w, h)

    if w < MIN_DIMENSION or h < MIN_DIMENSION:
        result["error"] = f"Image too small ({w}×{h}). Minimum: {MIN_DIMENSION}×{MIN_DIMENSION} px."
        return result

    if w > MAX_DIMENSION or h > MAX_DIMENSION:
        result["error"] = f"Image too large ({w}×{h}). Maximum: {MAX_DIMENSION}×{MAX_DIMENSION} px."
        return result

    # Convert to RGB if necessary (e.g. RGBA, palette mode)
    if img.mode not in ("RGB", "L"):
        try:
            img = img.convert("RGB")
        except Exception:
            pass  # Keep original mode, OCR may still work

    result["valid"] = True
    result["image"] = img
    return result


def extract_text_ocr(image) -> Dict[str, Any]:
    """
    Run Tesseract OCR on a PIL Image object.

    Args:
        image: A PIL.Image.Image instance.

    Returns:
        dict with keys: text, confidence, error, available
    """
    result = {
        "text": "",
        "confidence": None,
        "error": None,
        "available": False,
    }

    if image is None:
        result["error"] = "No image provided for OCR."
        return result

    # Check pytesseract availability
    try:
        import pytesseract
    except ImportError:
        result["error"] = (
            "pytesseract is not installed. "
            "Install with: pip install pytesseract\n"
            "Also requires system Tesseract: sudo dnf install tesseract (Fedora) "
            "or sudo apt-get install tesseract-ocr (Ubuntu/Debian)."
        )
        return result

    if not is_tesseract_available():
        result["error"] = (
            "Tesseract OCR binary not found. "
            "Install with: sudo dnf install tesseract (Fedora) "
            "or sudo apt-get install tesseract-ocr (Ubuntu/Debian)."
        )
        return result

    try:
        # Extract text with confidence data
        data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
        texts = []
        confidences = []
        for i, text in enumerate(data.get("text", [])):
            conf = data.get("conf", [0])[i]
            if text and text.strip():
                texts.append(text.strip())
                try:
                    c = float(conf)
                    if c > 0:
                        confidences.append(c)
                except (ValueError, TypeError):
                    pass

        extracted = " ".join(texts)
        avg_confidence = sum(confidences) / len(confidences) if confidences else None

        result["text"] = extracted
        result["confidence"] = round(avg_confidence, 1) if avg_confidence is not None else None
        result["available"] = True

        if not extracted.strip():
            result["error"] = "OCR completed but no text was detected in the image."

    except Exception as exc:
        result["error"] = f"OCR processing error: {exc}"
        logger.error("OCR extraction failed: %s", exc)

    return result
