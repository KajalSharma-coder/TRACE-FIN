import io
import os
import sys
import pytest
from PIL import Image

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src import ocr_engine
from src.ocr_engine import validate_image, extract_text_ocr, is_tesseract_available


class MockUploadedFile:
    """Mock Streamlit UploadedFile object."""
    def __init__(self, name: str, data: bytes):
        self.name = name
        self._io = io.BytesIO(data)
        self.size = len(data)

    def read(self, *args, **kwargs):
        return self._io.read(*args, **kwargs)

    def seek(self, *args, **kwargs):
        return self._io.seek(*args, **kwargs)


def _create_test_image(format="JPEG", size=(200, 100), color=(255, 0, 0)) -> bytes:
    """Create in-memory image bytes."""
    buf = io.BytesIO()
    img = Image.new("RGB", size, color=color)
    img.save(buf, format=format)
    return buf.getvalue()


def test_validate_image_valid_jpeg():
    raw = _create_test_image("JPEG", (300, 150))
    mock = MockUploadedFile("banner.jpg", raw)
    res = validate_image(mock)
    assert res["valid"] is True
    assert res["error"] is None
    assert res["dimensions"] == (300, 150)
    assert res["file_size_kb"] > 0
    assert res["image"] is not None


def test_validate_image_valid_png():
    raw = _create_test_image("PNG", (250, 120))
    mock = MockUploadedFile("ad.png", raw)
    res = validate_image(mock)
    assert res["valid"] is True
    assert res["error"] is None


def test_validate_image_none():
    res = validate_image(None)
    assert res["valid"] is False
    assert "No file" in res["error"]


def test_validate_image_empty():
    mock = MockUploadedFile("empty.jpg", b"")
    res = validate_image(mock)
    assert res["valid"] is False
    assert "empty" in res["error"].lower()


def test_validate_image_unsupported_extension():
    raw = _create_test_image("JPEG")
    mock = MockUploadedFile("document.pdf", raw)
    res = validate_image(mock)
    assert res["valid"] is False
    assert "Unsupported file type" in res["error"]


def test_validate_image_corrupt_bytes():
    mock = MockUploadedFile("fake.jpg", b"NOT_AN_IMAGE_HEADER_1234567890")
    res = validate_image(mock)
    assert res["valid"] is False
    assert "Corrupt" in res["error"] or "unreadable" in res["error"]


def test_validate_image_undersized():
    raw = _create_test_image("JPEG", (20, 20))
    mock = MockUploadedFile("tiny.jpg", raw)
    res = validate_image(mock)
    assert res["valid"] is False
    assert "too small" in res["error"].lower()


def test_extract_text_ocr_none_image():
    res = extract_text_ocr(None)
    assert res["available"] is False
    assert "No image provided" in res["error"]


def test_is_tesseract_available_boolean():
    avail = is_tesseract_available()
    assert isinstance(avail, bool)


def test_easyocr_result_normalizes_confidence(monkeypatch):
    monkeypatch.setenv("TRACEFIN_OCR_ENGINE", "auto")
    monkeypatch.setattr(ocr_engine, "_extract_easyocr", lambda _image: {
        "text": "Loan offer", "confidence": 91.2, "error": None,
        "available": True, "engine": "EasyOCR",
    })
    result = extract_text_ocr(Image.new("RGB", (100, 100)))
    assert result["available"] is True
    assert result["text"] == "Loan offer"
    assert result["engine"] == "EasyOCR"


def test_easyocr_error_falls_back_to_tesseract(monkeypatch):
    class _Output:
        DICT = "dict"

    class _Tesseract:
        Output = _Output

        @staticmethod
        def image_to_data(_image, output_type=None):
            assert output_type == "dict"
            return {"text": ["Approved", "loan"], "conf": ["90", "80"]}

    monkeypatch.setenv("TRACEFIN_OCR_ENGINE", "auto")
    monkeypatch.setattr(ocr_engine, "_extract_easyocr", lambda _image: (_ for _ in ()).throw(RuntimeError("weights unavailable")))
    monkeypatch.setattr(ocr_engine, "is_tesseract_available", lambda: True)
    monkeypatch.setitem(sys.modules, "pytesseract", _Tesseract())
    result = extract_text_ocr(Image.new("RGB", (100, 100)))
    assert result["available"] is True
    assert result["engine"] == "Tesseract"
    assert result["text"] == "Approved loan"
    assert result["confidence"] == 85.0
