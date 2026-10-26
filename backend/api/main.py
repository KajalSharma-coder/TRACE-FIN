"""Minimal FastAPI foundation for TRACE-FIN."""

import logging
import io
import math
import os
import secrets

import pandas as pd

from fastapi import Cookie, Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.auth import (
    AUTH_COOKIE_NAME,
    AUTH_SESSION_DAYS,
    AuthStoreError,
    DuplicateAccountError,
    authenticate_user,
    create_auth_session,
    create_user,
    get_user_by_auth_session,
    revoke_auth_session,
)

from src.analysis_service import run_unified_analysis
from src.dashboard import build_dashboard_snapshot
from src.database import get_all_records, get_record, search_records, update_status
from config import CASE_STATUSES, STANDARDIZED_RISK_TIERS
from src.browser_analysis import redact_sensitive_text, _redact_url
from src.evidence_graph import build_evidence_graph
from src.url_fetcher import analyze_url
from src.ocr_engine import ALLOWED_MIME_PREFIXES, MAX_FILE_SIZE_MB, extract_text_ocr, validate_image
from src.document_extractor import (
    MAX_FILE_SIZE_MB as MAX_DOCUMENT_FILE_SIZE_MB,
    extract_docx_text,
    extract_pdf_text,
)
from src.csv_analyzer import MAX_ROWS, MAX_SIZE_MB, export_safe_csv, run_batch_analysis, validate_csv
from src.recommendations import get_case_recommendation

from .schemas import (
    AnalysisRequest,
    AnalysisResponse,
    AuthResponse,
    AuthUser,
    CsrfResponse,
    DashboardRecentRecord,
    DashboardResponse,
    RedirectResponse,
    UrlAnalysisRequest,
    UrlAnalysisResponse,
    UrlModelResponse,
    ImageOcrResponse,
    ImageTextRequest,
    OcrResponse,
    DocumentExtractionResponse,
    DocumentTextRequest,
    CsvBatchResponse,
    CsvRowResponse,
    CsvSummaryResponse,
    InvestigationDetailResponse,
    InvestigationListResponse,
    InvestigationStatusRequest,
    InvestigationSummary,
    EvidenceEdgeResponse,
    EvidenceGraphResponse,
    EvidenceNodeResponse,
    ReportRecordResponse,
    ReportResponse,
    ReportSummaryResponse,
    LoginRequest,
    SignupRequest,
    analysis_response_from_result,
)

logger = logging.getLogger(__name__)
CSRF_COOKIE_NAME = "tracefin_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"


def _public_signup_enabled() -> bool:
    return os.getenv("TRACEFIN_PUBLIC_SIGNUP_ENABLED", "false").strip().lower() in {
        "1", "true", "yes", "on"
    }


def _development_origins() -> list[str]:
    configured = os.getenv(
        "TRACEFIN_API_ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    )
    origins = [origin.strip() for origin in configured.split(",") if origin.strip()]
    if not origins or "*" in origins:
        raise RuntimeError("TRACEFIN_API_ALLOWED_ORIGINS must contain explicit origins")
    return origins


app = FastAPI(title="TRACE-FIN API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_development_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", CSRF_HEADER_NAME],
)


def _cookie_secure() -> bool:
    return os.getenv("TRACEFIN_AUTH_COOKIE_SECURE", "true").strip().lower() in {
        "1", "true", "yes", "on"
    }


def _set_csrf_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        max_age=AUTH_SESSION_DAYS * 24 * 60 * 60,
        path="/",
        secure=_cookie_secure(),
        httponly=False,
        samesite="strict",
    )


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        max_age=AUTH_SESSION_DAYS * 24 * 60 * 60,
        path="/",
        secure=_cookie_secure(),
        httponly=True,
        samesite="strict",
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(AUTH_COOKIE_NAME, path="/")
    response.delete_cookie(CSRF_COOKIE_NAME, path="/")


def _require_csrf(csrf_cookie: str | None, csrf_header: str | None) -> None:
    if not csrf_cookie or not csrf_header:
        raise HTTPException(status_code=403, detail="CSRF validation failed.")
    if len(csrf_cookie) > 256 or len(csrf_header) > 256:
        raise HTTPException(status_code=403, detail="CSRF validation failed.")
    if not secrets.compare_digest(csrf_cookie, csrf_header):
        raise HTTPException(status_code=403, detail="CSRF validation failed.")


def _safe_auth_response(user: dict) -> AuthResponse:
    return AuthResponse(
        user=AuthUser(id=int(user["id"]), name=str(user["name"]), email=str(user["email"]))
    )


def _require_authenticated_user(
    session_cookie: str | None = Cookie(default=None, alias=AUTH_COOKIE_NAME),
) -> dict:
    """Resolve the existing session for protected read-only API routes."""
    if not session_cookie:
        raise HTTPException(status_code=401, detail="Authentication required.")
    try:
        user = get_user_by_auth_session(session_cookie)
    except AuthStoreError:
        raise HTTPException(status_code=503, detail="Authentication service unavailable.")
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


def _dashboard_response(snapshot: dict) -> DashboardResponse:
    recent = [
        DashboardRecentRecord(
            record_id=str(record.get("record_id", "")),
            advertisement=str(record.get("ad_text") or "")[:90],
            risk_score=record.get("risk_score"),
            risk_level=str(record.get("risk_level") or "—"),
            status=str(record.get("investigation_status") or "—"),
            submitted_at=str(record.get("submitted_at") or ""),
        )
        for record in snapshot.get("recent", [])
    ]
    return DashboardResponse(
        total=int(snapshot.get("total", 0)),
        risk_counts={str(key): int(value) for key, value in snapshot.get("risk_counts", {}).items()},
        status_counts={str(key): int(value) for key, value in snapshot.get("status_counts", {}).items()},
        activity=[
            {"date": str(item.get("date") or ""), "count": int(item.get("count", 0))}
            for item in snapshot.get("activity", [])
        ],
        category_counts={str(key): int(value) for key, value in snapshot.get("category_counts", {}).items()},
        recent=recent,
        demo_count=int(snapshot.get("demo_count", 0)),
    )


def _investigation_summary(record: dict) -> InvestigationSummary:
    return InvestigationSummary(
        record_id=str(record.get("record_id") or ""),
        advertisement=str(record.get("ad_text") or "")[:500],
        risk_score=record.get("risk_score"),
        risk_level=str(record.get("risk_level") or "Low"),
        status=str(record.get("investigation_status") or "Open"),
        submitted_at=str(record.get("submitted_at") or ""),
        analysis_mode=str(record.get("analysis_mode") or "rule_based"),
        review_required=bool(record.get("review_required")),
        review_recommendation=get_case_recommendation(record),
    )


def _investigation_detail(record: dict) -> InvestigationDetailResponse:
    summary = _investigation_summary(record)
    return InvestigationDetailResponse(
        **summary.model_dump(),
        ad_text=str(record.get("ad_text") or "")[:200_000],
        matched_categories=[str(value) for value in (record.get("matched_categories") or [])],
        urls=[str(value) for value in (record.get("urls") or [])],
        emails=[str(value) for value in (record.get("emails") or [])],
        phone_numbers=[str(value) for value in (record.get("phone_numbers") or [])],
        payment_identifiers=[str(value) for value in (record.get("payment_identifiers") or [])],
        ml_prediction=record.get("ml_prediction"),
        ml_confidence=record.get("ml_confidence"),
        hf_prediction=record.get("hf_prediction"),
        hf_confidence=record.get("hf_confidence"),
    )


def _evidence_graph_response(record: dict, graph: dict) -> EvidenceGraphResponse:
    nodes = [
        EvidenceNodeResponse(
            id=str(node.get("id") or ""),
            type=str(node.get("type") or "unknown"),
            label=str(node.get("label") or "Evidence"),
            value=str(node.get("value") or "")[:500],
            source=str(node.get("source") or "")[:200],
            reason=str(node.get("reason") or "")[:500],
            risk=str(node.get("risk") or "medium"),
            confidence=node.get("confidence"),
            related_ids=[str(value) for value in (node.get("related_ids") or [])],
        )
        for node in graph.get("nodes", [])
    ]
    edges = [
        EvidenceEdgeResponse(
            source=str(edge.get("source") or ""),
            target=str(edge.get("target") or ""),
            label=str(edge.get("label") or "related to"),
        )
        for edge in graph.get("edges", [])
    ]
    return EvidenceGraphResponse(
        record_id=str(record.get("record_id") or ""),
        submitted_at=str(record.get("submitted_at") or ""),
        analysis_mode=str(record.get("analysis_mode") or "rule_based"),
        central_id=str(graph.get("central_id") or ""),
        classification=str(graph.get("classification") or "Advertisement analyzed"),
        risk_score=graph.get("risk_score"),
        evidence_count=int(graph.get("evidence_count") or 0),
        high_risk_count=int(graph.get("high_risk_count") or 0),
        nodes=nodes,
        edges=edges,
    )


def _report_record(record: dict) -> ReportRecordResponse:
    def joined(key: str) -> str:
        return "; ".join(str(value) for value in (record.get(key) or []))

    return ReportRecordResponse(
        record_id=str(record.get("record_id") or ""),
        advertisement_text=str(record.get("ad_text") or "")[:5000],
        risk_score=record.get("risk_score"),
        risk_level=str(record.get("risk_level") or "Low"),
        ml_prediction=str(record.get("ml_prediction")) if record.get("ml_prediction") is not None else None,
        ml_confidence=record.get("ml_confidence"),
        review_required=bool(record.get("review_required")),
        review_recommendation=str(record.get("review_recommendation") or "No Immediate Review Indicated"),
        matched_categories=joined("matched_categories"),
        extracted_urls=joined("urls"),
        extracted_emails=joined("emails"),
        extracted_phone_numbers=joined("phone_numbers"),
        extracted_payment_ids=joined("payment_identifiers"),
        investigation_status=str(record.get("investigation_status") or "Open"),
        analysis_mode=str(record.get("analysis_mode") or "rule_based"),
        is_synthetic=bool(record.get("is_synthetic")),
        submitted_at=str(record.get("submitted_at") or ""),
    )


def _safe_url_model(result: dict | None) -> UrlModelResponse:
    model = result or {}
    return UrlModelResponse(
        available=bool(model.get("available")),
        prediction=model.get("prediction"),
        phishing_probability=model.get("phishing_probability"),
        model=str(model.get("model")) if model.get("model") else None,
        error="URL model unavailable." if not model.get("available") and model.get("error") else None,
    )


def _url_analysis_response(result: dict) -> UrlAnalysisResponse:
    redirect_history = [
        RedirectResponse(
            source=_redact_url(str(hop.get("from") or "")) or "",
            destination=_redact_url(str(hop.get("to") or "")) or "",
            status=int(hop.get("status", 0)),
        )
        for hop in result.get("redirect_history", [])
    ]
    return UrlAnalysisResponse(
        valid=bool(result.get("valid")),
        success=bool(result.get("success")),
        url=_redact_url(str(result.get("url") or "")) or "",
        final_url=_redact_url(str(result.get("final_url") or result.get("url") or "")) or "",
        error=str(result.get("error")) if result.get("error") else None,
        failure_category=result.get("failure_category"),
        analysis_mode=str(result.get("analysis_mode") or "syntax_only"),
        disclosure=str(result.get("disclosure") or ""),
        hostname=str(result.get("hostname")) if result.get("hostname") else None,
        title=redact_sensitive_text(str(result.get("title") or "")),
        extracted_text=redact_sensitive_text(str(result.get("extracted_text") or "")),
        indicators=[str(item) for item in (result.get("indicators") or [])],
        warnings=[str(item) for item in (result.get("warnings") or [])],
        status_code=result.get("status_code"),
        bytes_downloaded=int(result.get("bytes_downloaded") or 0),
        redirect_history=redirect_history,
        url_model=_safe_url_model(result.get("url_model")),
        advertisement_analysis=(
            analysis_response_from_result(result["advertisement_analysis"])
            if result.get("advertisement_analysis") is not None
            else None
        ),
    )


def _safe_image_validation_error(message: str | None) -> str:
    text = (message or "Image validation failed.").lower()
    if "corrupt" in text or "unreadable" in text:
        return "Corrupt or unreadable image file."
    if "too large" in text:
        return message or "Image exceeds the supported size or dimensions."
    if "too small" in text:
        return message or "Image dimensions are below the supported minimum."
    if "unsupported file type" in text or "not supported" in text:
        return "Unsupported image type. Accepted formats: JPEG, PNG, WEBP."
    if "empty" in text:
        return "Uploaded image is empty."
    return "Image validation failed."


def _safe_ocr_response(result: dict) -> OcrResponse:
    error = result.get("error")
    safe_error = None
    if error:
        safe_error = "OCR completed without readable text." if result.get("available") else "OCR engine unavailable or failed."
    return OcrResponse(
        text=str(result.get("text") or ""),
        confidence=result.get("confidence"),
        error=safe_error,
        available=bool(result.get("available")),
        engine=str(result.get("engine")) if result.get("engine") else None,
    )


def _safe_document_error(message: str | None) -> str | None:
    if not message:
        return None
    lowered = message.lower()
    if "size" in lowered or "limit" in lowered or "maximum" in lowered:
        return message
    if "page" in lowered and "30" in lowered:
        return message
    if "paragraph" in lowered or "character" in lowered or "row" in lowered:
        return message
    if "encrypted" in lowered or "password" in lowered:
        return "Document is encrypted or password-protected."
    if "zip bomb" in lowered or "compression ratio" in lowered:
        return "Document archive failed ZIP safety validation."
    if "invalid" in lowered or "signature" in lowered or "format" in lowered or "corrupt" in lowered or "malformed" in lowered:
        return "Document is malformed or has an unsupported format."
    return "Document extraction failed."


def _document_response(result: dict, source_type: str) -> DocumentExtractionResponse:
    allowed_metadata = {
        key: value
        for key, value in (result.get("metadata") or {}).items()
        if key in {
            "total_pages", "size_kb", "pages_extracted", "characters_extracted",
            "paragraphs_extracted", "table_rows_extracted", "encrypted",
        } and isinstance(value, (int, float, bool))
    }
    return DocumentExtractionResponse(
        valid=bool(result.get("valid")),
        source_type=source_type,
        text=str(result.get("text") or ""),
        error=_safe_document_error(result.get("error")),
        warnings=[str(item) for item in (result.get("warnings") or [])],
        metadata=allowed_metadata,
    )


async def _read_document_upload(document: UploadFile) -> io.BytesIO:
    max_bytes = MAX_DOCUMENT_FILE_SIZE_MB * 1024 * 1024
    payload = await document.read(max_bytes + 1)
    stream = io.BytesIO(payload)
    stream.name = document.filename or "upload"
    stream.size = len(payload)
    return stream


@app.exception_handler(RequestValidationError)
async def request_validation_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    del request, exc
    return JSONResponse(status_code=422, content={"detail": "Invalid request."})


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "trace-fin-api"}


@app.get("/api/dashboard", response_model=DashboardResponse)
def dashboard(_user: dict = Depends(_require_authenticated_user)) -> DashboardResponse:
    """Return the existing dashboard aggregation for the authenticated user."""
    del _user
    try:
        snapshot = build_dashboard_snapshot(get_all_records())
        return _dashboard_response(snapshot)
    except Exception as exc:  # pragma: no cover - exercised through failure injection
        logger.error("Dashboard API failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Dashboard data unavailable.")


@app.get("/api/auth/csrf", response_model=CsrfResponse)
def csrf_token(
    response: Response,
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE_NAME),
) -> CsrfResponse:
    token = csrf_cookie if csrf_cookie and len(csrf_cookie) <= 256 else secrets.token_urlsafe(32)
    _set_csrf_cookie(response, token)
    return CsrfResponse(csrf_token=token)


@app.post("/api/auth/login", response_model=AuthResponse)
def login(
    credentials: LoginRequest,
    response: Response,
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE_NAME),
    csrf_header: str | None = Header(default=None, alias=CSRF_HEADER_NAME),
) -> AuthResponse:
    _require_csrf(csrf_cookie, csrf_header)
    try:
        user = authenticate_user(credentials.email, credentials.password)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        session_token = create_auth_session(user["id"])
        _set_session_cookie(response, session_token)
        return _safe_auth_response(user)
    except AuthStoreError:
        raise HTTPException(status_code=503, detail="Authentication service unavailable.")


@app.post("/api/auth/register", response_model=AuthResponse, status_code=201)
def register(
    credentials: SignupRequest,
    response: Response,
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE_NAME),
    csrf_header: str | None = Header(default=None, alias=CSRF_HEADER_NAME),
) -> AuthResponse:
    _require_csrf(csrf_cookie, csrf_header)
    if not _public_signup_enabled():
        raise HTTPException(status_code=403, detail="Public registration is disabled.")
    try:
        user = create_user(
            credentials.name,
            credentials.email,
            credentials.password,
            credentials.confirmation,
        )
        session_token = create_auth_session(user["id"])
        _set_session_cookie(response, session_token)
        return _safe_auth_response(user)
    except DuplicateAccountError:
        raise HTTPException(status_code=409, detail="An account already exists for this email address.")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except AuthStoreError:
        raise HTTPException(status_code=503, detail="Authentication service unavailable.")


@app.get("/api/auth/session", response_model=AuthResponse)
def current_session(
    response: Response,
    session_cookie: str | None = Cookie(default=None, alias=AUTH_COOKIE_NAME),
) -> AuthResponse:
    if not session_cookie:
        raise HTTPException(status_code=401, detail="Authentication required.")
    try:
        user = get_user_by_auth_session(session_cookie)
    except AuthStoreError:
        raise HTTPException(status_code=503, detail="Authentication service unavailable.")
    if user is None:
        _clear_auth_cookies(response)
        raise HTTPException(status_code=401, detail="Authentication required.")
    return _safe_auth_response(user)


@app.post("/api/auth/logout", status_code=204)
def logout(
    session_cookie: str | None = Cookie(default=None, alias=AUTH_COOKIE_NAME),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE_NAME),
    csrf_header: str | None = Header(default=None, alias=CSRF_HEADER_NAME),
) -> Response:
    _require_csrf(csrf_cookie, csrf_header)
    try:
        if session_cookie:
            revoke_auth_session(session_cookie)
    except AuthStoreError:
        raise HTTPException(status_code=503, detail="Authentication service unavailable.")
    logout_response = Response(status_code=204)
    _clear_auth_cookies(logout_response)
    return logout_response


@app.post("/api/analyze", response_model=AnalysisResponse)
def analyze(
    request: AnalysisRequest,
    _user: dict = Depends(_require_authenticated_user),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE_NAME),
    csrf_header: str | None = Header(default=None, alias=CSRF_HEADER_NAME),
) -> AnalysisResponse:
    del _user
    _require_csrf(csrf_cookie, csrf_header)
    try:
        result = run_unified_analysis(text=request.text, source_type="Direct Text")
        return analysis_response_from_result(result)
    except Exception as exc:  # pragma: no cover - exercised through failure injection
        logger.error("API analysis failed: %s", type(exc).__name__)
        return JSONResponse(status_code=503, content={"detail": "Analysis service unavailable."})


@app.post("/api/analyze-url", response_model=UrlAnalysisResponse)
def analyze_url_endpoint(
    request: UrlAnalysisRequest,
    _user: dict = Depends(_require_authenticated_user),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE_NAME),
    csrf_header: str | None = Header(default=None, alias=CSRF_HEADER_NAME),
) -> UrlAnalysisResponse:
    del _user
    _require_csrf(csrf_cookie, csrf_header)
    try:
        result = analyze_url(request.url.strip(), fetch_content=request.fetch_content)
        extracted_text = str(result.get("extracted_text") or "")
        if extracted_text.strip():
            result = dict(result)
            result["advertisement_analysis"] = run_unified_analysis(
                text=extracted_text,
                source_type="URL Content",
            )
        return _url_analysis_response(result)
    except Exception as exc:  # pragma: no cover - exercised through failure injection
        logger.error("URL analysis API failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="URL analysis service unavailable.")


@app.post("/api/image-ocr", response_model=ImageOcrResponse)
async def image_ocr(
    image: UploadFile = File(...),
    _user: dict = Depends(_require_authenticated_user),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE_NAME),
    csrf_header: str | None = Header(default=None, alias=CSRF_HEADER_NAME),
) -> ImageOcrResponse:
    del _user
    _require_csrf(csrf_cookie, csrf_header)
    if image.content_type not in ALLOWED_MIME_PREFIXES:
        raise HTTPException(status_code=422, detail="Unsupported image content type.")
    try:
        max_bytes = MAX_FILE_SIZE_MB * 1024 * 1024
        payload = await image.read(max_bytes + 1)
        if len(payload) > max_bytes:
            return ImageOcrResponse(
                valid=False,
                error=f"Image exceeds the {MAX_FILE_SIZE_MB} MB upload limit.",
                file_size_kb=round(len(payload) / 1024, 1),
                dimensions=[0, 0],
                ocr=OcrResponse(text="", confidence=None, error=None, available=False, engine=None),
            )
        upload = io.BytesIO(payload)
        upload.name = image.filename or "upload"
        upload.size = len(payload)
        validation = validate_image(upload)
        if not validation.get("valid"):
            return ImageOcrResponse(
                valid=False,
                error=_safe_image_validation_error(validation.get("error")),
                file_size_kb=float(validation.get("file_size_kb") or 0),
                dimensions=[int(value) for value in validation.get("dimensions", (0, 0))],
                ocr=OcrResponse(text="", confidence=None, error=None, available=False, engine=None),
            )
        ocr_result = extract_text_ocr(validation.get("image"))
        return ImageOcrResponse(
            valid=True,
            error=None,
            file_size_kb=float(validation.get("file_size_kb") or 0),
            dimensions=[int(value) for value in validation.get("dimensions", (0, 0))],
            ocr=_safe_ocr_response(ocr_result),
        )
    except Exception as exc:  # pragma: no cover - exercised through failure injection
        logger.error("Image OCR API failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Image OCR service unavailable.")


@app.post("/api/analyze-image-text", response_model=AnalysisResponse)
def analyze_image_text(
    request: ImageTextRequest,
    _user: dict = Depends(_require_authenticated_user),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE_NAME),
    csrf_header: str | None = Header(default=None, alias=CSRF_HEADER_NAME),
) -> AnalysisResponse:
    del _user
    _require_csrf(csrf_cookie, csrf_header)
    try:
        result = run_unified_analysis(text=request.text, source_type="Image OCR")
        return analysis_response_from_result(result)
    except Exception as exc:  # pragma: no cover - exercised through failure injection
        logger.error("Image text analysis API failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Analysis service unavailable.")


@app.post("/api/document/pdf", response_model=DocumentExtractionResponse)
async def extract_pdf_endpoint(
    document: UploadFile = File(...),
    _user: dict = Depends(_require_authenticated_user),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE_NAME),
    csrf_header: str | None = Header(default=None, alias=CSRF_HEADER_NAME),
) -> DocumentExtractionResponse:
    del _user
    _require_csrf(csrf_cookie, csrf_header)
    if document.content_type != "application/pdf":
        raise HTTPException(status_code=422, detail="Unsupported PDF content type.")
    try:
        upload = await _read_document_upload(document)
        result = extract_pdf_text(upload)
        return _document_response(result, "PDF Document")
    except Exception as exc:  # pragma: no cover - exercised through failure injection
        logger.error("PDF extraction API failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="PDF extraction service unavailable.")


@app.post("/api/document/docx", response_model=DocumentExtractionResponse)
async def extract_docx_endpoint(
    document: UploadFile = File(...),
    _user: dict = Depends(_require_authenticated_user),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE_NAME),
    csrf_header: str | None = Header(default=None, alias=CSRF_HEADER_NAME),
) -> DocumentExtractionResponse:
    del _user
    _require_csrf(csrf_cookie, csrf_header)
    if document.content_type != "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
        raise HTTPException(status_code=422, detail="Unsupported DOCX content type.")
    try:
        upload = await _read_document_upload(document)
        result = extract_docx_text(upload)
        return _document_response(result, "DOCX Document")
    except Exception as exc:  # pragma: no cover - exercised through failure injection
        logger.error("DOCX extraction API failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="DOCX extraction service unavailable.")


def _analyze_document_text(request: DocumentTextRequest, source_type: str) -> AnalysisResponse:
    result = run_unified_analysis(text=request.text, source_type=source_type)
    return analysis_response_from_result(result)


def _csv_scalar(value):
    if value is None:
        return None
    if isinstance(value, float) and math.isnan(value):
        return None
    if hasattr(value, "item"):
        value = value.item()
    return value


def _csv_row_response(row: dict) -> CsvRowResponse:
    def text_value(key: str, default: str = "") -> str:
        value = _csv_scalar(row.get(key))
        return default if value is None else str(value)

    return CsvRowResponse(
        row_index=int(_csv_scalar(row.get("row_index")) or 0),
        original_text=text_value("original_text")[:500],
        final_verdict=text_value("final_verdict") or None,
        final_score=_csv_scalar(row.get("final_score")),
        risk_score=_csv_scalar(row.get("risk_score")),
        risk_level=text_value("risk_level") or None,
        rule_score=_csv_scalar(row.get("rule_score")),
        rule_level=text_value("rule_level") or None,
        matched_categories=text_value("matched_categories"),
        tfidf_status=text_value("tfidf_status") or None,
        distilbert_status=text_value("distilbert_status") or None,
        recommendation=text_value("recommendation"),
        investigation_status=text_value("investigation_status") or None,
        review_required=_csv_scalar(row.get("review_required")),
        validation_status=text_value("validation_status"),
        ground_truth=text_value("ground_truth") or None,
    )


def _csv_summary(rows: list[dict]) -> CsvSummaryResponse:
    statuses = [str(_csv_scalar(row.get("validation_status")) or "") for row in rows]
    levels = [str(_csv_scalar(row.get("risk_level")) or "") for row in rows]
    return CsvSummaryResponse(
        total_rows=len(rows),
        successful_rows=sum(status == "OK" for status in statuses),
        invalid_rows=sum(status.startswith("INVALID") for status in statuses),
        failed_rows=sum(status.startswith("FAILED") for status in statuses),
        skipped_rows=sum(status.startswith("SKIPPED") for status in statuses),
        critical_count=levels.count("Critical"),
        high_count=levels.count("High"),
        medium_count=levels.count("Medium"),
        low_count=levels.count("Low"),
        unscored_count=levels.count("Unscored") + sum(not level for level in levels),
    )


def _empty_csv_response(error: str, columns: list[str] | None = None, row_count: int = 0) -> CsvBatchResponse:
    return CsvBatchResponse(
        valid=False,
        error=error,
        columns=columns or [],
        row_count=row_count,
        text_column=None,
        label_column=None,
        results=[],
        summary=_csv_summary([]),
        export_csv=None,
    )


@app.post("/api/analyze-pdf-text", response_model=AnalysisResponse)
def analyze_pdf_text(
    request: DocumentTextRequest,
    _user: dict = Depends(_require_authenticated_user),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE_NAME),
    csrf_header: str | None = Header(default=None, alias=CSRF_HEADER_NAME),
) -> AnalysisResponse:
    del _user
    _require_csrf(csrf_cookie, csrf_header)
    try:
        return _analyze_document_text(request, "PDF Document")
    except Exception as exc:  # pragma: no cover - exercised through failure injection
        logger.error("PDF text analysis API failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Analysis service unavailable.")


@app.post("/api/analyze-docx-text", response_model=AnalysisResponse)
def analyze_docx_text(
    request: DocumentTextRequest,
    _user: dict = Depends(_require_authenticated_user),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE_NAME),
    csrf_header: str | None = Header(default=None, alias=CSRF_HEADER_NAME),
) -> AnalysisResponse:
    del _user
    _require_csrf(csrf_cookie, csrf_header)
    try:
        return _analyze_document_text(request, "DOCX Document")
    except Exception as exc:  # pragma: no cover - exercised through failure injection
        logger.error("DOCX text analysis API failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Analysis service unavailable.")


@app.post("/api/analyze-csv", response_model=CsvBatchResponse)
async def analyze_csv_endpoint(
    csv_file: UploadFile = File(...),
    text_column: str | None = Form(default=None),
    label_column: str | None = Form(default=None),
    include_hf: bool = Form(default=False),
    _user: dict = Depends(_require_authenticated_user),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE_NAME),
    csrf_header: str | None = Header(default=None, alias=CSRF_HEADER_NAME),
) -> CsvBatchResponse:
    del _user
    _require_csrf(csrf_cookie, csrf_header)
    allowed_types = {"text/csv", "application/csv", "application/vnd.ms-excel", "application/octet-stream"}
    if csv_file.content_type not in allowed_types:
        raise HTTPException(status_code=422, detail="Unsupported CSV content type.")
    if not (csv_file.filename or "").lower().endswith(".csv"):
        raise HTTPException(status_code=422, detail="CSV filename must use the .csv extension.")
    try:
        payload = await csv_file.read(int(MAX_SIZE_MB * 1024 * 1024) + 1)
        upload = io.BytesIO(payload)
        upload.name = csv_file.filename or "upload.csv"
        validation = validate_csv(upload, max_rows=MAX_ROWS, max_size_mb=MAX_SIZE_MB)
        if not validation.get("valid"):
            return _empty_csv_response(str(validation.get("error") or "CSV validation failed."), validation.get("columns"), int(validation.get("row_count") or 0))

        columns = [str(column) for column in validation.get("columns", [])]
        selected_text = (text_column or "").strip()
        selected_label = (label_column or "").strip() or None
        if not selected_text:
            return CsvBatchResponse(
                valid=True,
                error=None,
                columns=columns,
                row_count=int(validation.get("row_count") or 0),
                text_column=None,
                label_column=None,
                results=[],
                summary=_csv_summary([]),
                export_csv=None,
            )
        if selected_text not in columns:
            raise HTTPException(status_code=422, detail="Selected text column was not found in the CSV.")
        if selected_label and selected_label not in columns:
            raise HTTPException(status_code=422, detail="Selected label column was not found in the CSV.")

        results_df = run_batch_analysis(
            df=validation["df"],
            text_column=selected_text,
            label_column=selected_label,
            include_hf=include_hf,
        )
        rows = results_df.to_dict(orient="records")
        response_rows = [_csv_row_response(row) for row in rows]
        export_columns = [
            "row_index", "original_text", "final_verdict", "final_score", "risk_score",
            "risk_level", "rule_score", "rule_level", "matched_categories", "tfidf_status",
            "distilbert_status", "recommendation", "investigation_status", "review_required",
            "validation_status", "ground_truth",
        ]
        export_df = results_df.reindex(columns=export_columns)
        return CsvBatchResponse(
            valid=True,
            error=None,
            columns=columns,
            row_count=int(validation.get("row_count") or 0),
            text_column=selected_text,
            label_column=selected_label,
            results=response_rows,
            summary=_csv_summary(rows),
            export_csv=export_safe_csv(export_df),
        )
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - exercised through failure injection
        logger.error("CSV analysis API failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="CSV analysis service unavailable.")


@app.get("/api/investigations", response_model=InvestigationListResponse)
def list_investigations(
    query: str = Query(default="", max_length=200),
    risk_level: str | None = Query(default=None, max_length=32),
    status: str | None = Query(default=None, max_length=32),
    _user: dict = Depends(_require_authenticated_user),
) -> InvestigationListResponse:
    del _user
    normalized_risk = risk_level.strip() if risk_level else None
    normalized_status = status.strip() if status else None
    if normalized_risk and normalized_risk not in STANDARDIZED_RISK_TIERS:
        raise HTTPException(status_code=422, detail="Unsupported investigation risk level.")
    if normalized_status and normalized_status not in CASE_STATUSES:
        raise HTTPException(status_code=422, detail="Unsupported investigation status.")
    try:
        records = search_records(query=query.strip(), risk_level=normalized_risk, status=normalized_status)
        return InvestigationListResponse(
            items=[_investigation_summary(record) for record in records],
            count=len(records),
            query=query.strip(),
            risk_level=normalized_risk,
            status=normalized_status,
        )
    except Exception as exc:  # pragma: no cover - exercised through failure injection
        logger.error("Investigation list API failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Investigation data unavailable.")


@app.get("/api/investigations/{record_id}", response_model=InvestigationDetailResponse)
def get_investigation(
    record_id: str,
    _user: dict = Depends(_require_authenticated_user),
) -> InvestigationDetailResponse:
    del _user
    if not record_id.strip() or len(record_id) > 64:
        raise HTTPException(status_code=422, detail="Invalid investigation record ID.")
    try:
        record = get_record(record_id.strip())
    except Exception as exc:  # pragma: no cover - exercised through failure injection
        logger.error("Investigation detail API failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Investigation data unavailable.")
    if record is None:
        raise HTTPException(status_code=404, detail="Investigation record not found.")
    return _investigation_detail(record)


@app.patch("/api/investigations/{record_id}/status", response_model=InvestigationDetailResponse)
def change_investigation_status(
    record_id: str,
    request: InvestigationStatusRequest,
    _user: dict = Depends(_require_authenticated_user),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE_NAME),
    csrf_header: str | None = Header(default=None, alias=CSRF_HEADER_NAME),
) -> InvestigationDetailResponse:
    del _user
    _require_csrf(csrf_cookie, csrf_header)
    normalized_id = record_id.strip()
    normalized_status = request.status.strip()
    if not normalized_id or len(normalized_id) > 64:
        raise HTTPException(status_code=422, detail="Invalid investigation record ID.")
    if normalized_status not in CASE_STATUSES:
        raise HTTPException(status_code=422, detail="Unsupported investigation status.")
    try:
        if not update_status(normalized_id, normalized_status):
            raise HTTPException(status_code=404, detail="Investigation record not found.")
        record = get_record(normalized_id)
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - exercised through failure injection
        logger.error("Investigation status API failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Investigation data unavailable.")
    if record is None:
        raise HTTPException(status_code=404, detail="Investigation record not found.")
    return _investigation_detail(record)


@app.get("/api/evidence/{record_id}", response_model=EvidenceGraphResponse)
def get_evidence_graph(
    record_id: str,
    _user: dict = Depends(_require_authenticated_user),
) -> EvidenceGraphResponse:
    del _user
    normalized_id = record_id.strip()
    if not normalized_id or len(normalized_id) > 64:
        raise HTTPException(status_code=422, detail="Invalid evidence record ID.")
    try:
        record = get_record(normalized_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Evidence record not found.")
        graph = build_evidence_graph(
            record,
            text=str(record.get("ad_text") or ""),
            source_type=str(record.get("analysis_mode") or "Advertisement analysis"),
            related_records=get_all_records(),
        )
        return _evidence_graph_response(record, graph)
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - exercised through failure injection
        logger.error("Evidence graph API failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Evidence data unavailable.")


@app.get("/api/reports/records", response_model=ReportResponse)
def records_report(
    query: str = Query(default="", max_length=200),
    risk_level: str | None = Query(default=None, max_length=32),
    status: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=500, ge=1, le=1000),
    _user: dict = Depends(_require_authenticated_user),
) -> ReportResponse:
    del _user
    normalized_risk = risk_level.strip() if risk_level else None
    normalized_status = status.strip() if status else None
    normalized_query = query.strip()
    if normalized_risk and normalized_risk not in STANDARDIZED_RISK_TIERS:
        raise HTTPException(status_code=422, detail="Unsupported report risk level.")
    if normalized_status and normalized_status not in CASE_STATUSES:
        raise HTTPException(status_code=422, detail="Unsupported report status.")
    try:
        records = search_records(query=normalized_query, risk_level=normalized_risk, status=normalized_status)
        risk_counts: dict[str, int] = {}
        status_counts: dict[str, int] = {}
        for record in records:
            risk_key = str(record.get("risk_level") or "Low")
            status_key = str(record.get("investigation_status") or "Open")
            risk_counts[risk_key] = risk_counts.get(risk_key, 0) + 1
            status_counts[status_key] = status_counts.get(status_key, 0) + 1
        bounded_records = records[:limit]
        report_records = [_report_record(record) for record in bounded_records]
        export_csv = None
        if report_records:
            export_csv = export_safe_csv(pd.DataFrame([record.model_dump() for record in report_records]))
        return ReportResponse(
            filters={"query": normalized_query, "risk_level": normalized_risk, "status": normalized_status, "limit": limit},
            summary=ReportSummaryResponse(
                total_matching=len(records),
                returned=len(report_records),
                truncated=len(records) > limit,
                risk_counts=risk_counts,
                status_counts=status_counts,
            ),
            records=report_records,
            export_csv=export_csv,
        )
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - exercised through failure injection
        logger.error("Records report API failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Report data unavailable.")
