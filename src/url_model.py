"""Optional ONNX URL phishing classifier supplied with TRACE//FIN.

This generic phishing signal supplements financial-ad analysis. It never changes
the deterministic financial-ad score or verdict.
"""

from functools import lru_cache
from pathlib import Path
from typing import Any
import logging

logger = logging.getLogger("tracefin.url_model")
MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "url_phishing_classifier.onnx"


@lru_cache(maxsize=1)
def _load_session():
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(f"URL model artifact is missing: {MODEL_PATH}")
    try:
        import onnxruntime as ort
    except ImportError as exc:
        raise RuntimeError("onnxruntime is not installed; install project requirements to enable URL classification.") from exc
    return ort.InferenceSession(str(MODEL_PATH), providers=["CPUExecutionProvider"])


def get_url_model_info() -> dict[str, Any]:
    """Return truthful local artifact/runtime status without loading untrusted pickle data."""
    if not MODEL_PATH.is_file():
        return {"available": False, "model": "pirocheto/phishing-url-detection (ONNX)", "error": "ONNX model artifact is missing."}
    try:
        session = _load_session()
        return {"available": True, "model": "pirocheto/phishing-url-detection (ONNX)",
                "input_name": session.get_inputs()[0].name, "output_names": [o.name for o in session.get_outputs()]}
    except Exception as exc:
        return {"available": False, "model": "pirocheto/phishing-url-detection (ONNX)", "error": str(exc)}


def classify_url(url: str) -> dict[str, Any]:
    """Classify a URL string and return a supplementary phishing likelihood."""
    result = {"available": False, "url": url, "prediction": None, "phishing_probability": None,
              "model": "pirocheto/phishing-url-detection (ONNX)", "error": None}
    if not isinstance(url, str) or not url.strip():
        result["error"] = "A non-empty URL is required."
        return result
    try:
        import numpy as np

        session = _load_session()
        input_meta = session.get_inputs()[0]
        outputs = session.run(None, {input_meta.name: np.asarray([url.strip()], dtype=str)})
        if len(outputs) < 2:
            raise ValueError("URL model output did not include class probabilities.")
        probabilities = np.asarray(outputs[1]).reshape(1, -1)[0]
        if probabilities.size < 2:
            raise ValueError("URL model returned fewer than two class probabilities.")
        phishing_probability = float(probabilities[1])
        if not 0.0 <= phishing_probability <= 1.0:
            raise ValueError("URL model returned an invalid probability.")
        result.update(available=True, prediction="Phishing-like" if phishing_probability >= 0.5 else "Not phishing-like",
                      phishing_probability=round(phishing_probability, 6))
    except Exception as exc:
        logger.warning("URL model inference unavailable: %s", exc)
        result["error"] = str(exc)
    return result
