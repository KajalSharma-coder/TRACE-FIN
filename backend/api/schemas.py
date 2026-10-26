"""Typed request and response models for the minimal TRACE-FIN API."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AnalysisRequest(BaseModel):
    """Direct-text analysis input exposed by the initial API."""

    model_config = ConfigDict(extra="forbid")

    text: str = Field(..., min_length=1, max_length=200_000)


class LoginRequest(BaseModel):
    """Credentials accepted by the browser login endpoint."""

    model_config = ConfigDict(extra="forbid")

    email: str = Field(..., min_length=1, max_length=254)
    password: str = Field(..., min_length=1, max_length=1024)


class SignupRequest(BaseModel):
    """Validated fields accepted by the browser registration endpoint."""

    model_config = ConfigDict(extra="forbid")

    # Empty/whitespace-only names are validated by ``validate_signup`` so the
    # endpoint can return its established field-specific message.
    name: str = Field(..., max_length=100)
    email: str = Field(..., min_length=1, max_length=254)
    password: str = Field(..., min_length=1, max_length=1024)
    confirmation: str = Field(..., min_length=1, max_length=1024)


class AuthUser(BaseModel):
    """Safe identity fields; password data is never part of this model."""

    model_config = ConfigDict(extra="forbid")

    id: int
    name: str
    email: str


class AuthResponse(BaseModel):
    user: AuthUser


class CsrfResponse(BaseModel):
    csrf_token: str


class DashboardRecentRecord(BaseModel):
    record_id: str
    advertisement: str
    risk_score: float | int | None
    risk_level: str
    status: str
    submitted_at: str


class DashboardResponse(BaseModel):
    total: int
    risk_counts: dict[str, int]
    status_counts: dict[str, int]
    activity: list[dict[str, int | str]]
    category_counts: dict[str, int]
    recent: list[DashboardRecentRecord]
    demo_count: int


class InvestigationSummary(BaseModel):
    record_id: str
    advertisement: str
    risk_score: float | int | None
    risk_level: str
    status: str
    submitted_at: str
    analysis_mode: str
    review_required: bool
    review_recommendation: str


class InvestigationListResponse(BaseModel):
    items: list[InvestigationSummary]
    count: int
    query: str
    risk_level: str | None
    status: str | None


class InvestigationDetailResponse(InvestigationSummary):
    ad_text: str
    matched_categories: list[str]
    urls: list[str]
    emails: list[str]
    phone_numbers: list[str]
    payment_identifiers: list[str]
    ml_prediction: str | None
    ml_confidence: float | None
    hf_prediction: str | None
    hf_confidence: float | None


class InvestigationStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., min_length=1, max_length=32)


class EvidenceNodeResponse(BaseModel):
    id: str
    type: str
    label: str
    value: str
    source: str
    reason: str
    risk: str
    confidence: float | None
    related_ids: list[str]


class EvidenceEdgeResponse(BaseModel):
    source: str
    target: str
    label: str


class EvidenceGraphResponse(BaseModel):
    record_id: str
    submitted_at: str
    analysis_mode: str
    central_id: str
    classification: str
    risk_score: int | float | None
    evidence_count: int
    high_risk_count: int
    nodes: list[EvidenceNodeResponse]
    edges: list[EvidenceEdgeResponse]


class ReportRecordResponse(BaseModel):
    record_id: str
    advertisement_text: str
    risk_score: float | int | None
    risk_level: str
    ml_prediction: str | None
    ml_confidence: float | None
    review_required: bool
    review_recommendation: str
    matched_categories: str
    extracted_urls: str
    extracted_emails: str
    extracted_phone_numbers: str
    extracted_payment_ids: str
    investigation_status: str
    analysis_mode: str
    is_synthetic: bool
    submitted_at: str


class ReportSummaryResponse(BaseModel):
    total_matching: int
    returned: int
    truncated: bool
    risk_counts: dict[str, int]
    status_counts: dict[str, int]


class ReportResponse(BaseModel):
    filters: dict[str, str | int | None]
    summary: ReportSummaryResponse
    records: list[ReportRecordResponse]
    export_csv: str | None


class AnalysisResponse(BaseModel):
    """Safe projection of the existing unified analysis result."""

    model_config = ConfigDict(extra="forbid")

    source_type: str
    extraction_status: str
    has_sufficient_evidence: bool
    final_verdict: str
    final_score: int | None
    risk_score: int | None
    risk_level: str
    rule_score: int | None
    rule_level: str
    matched_categories: list[str]
    evidence: list[str]
    explanation: str
    recommendation: str
    investigation_status: str
    review_required: bool
    consensus_status: str
    engine_status: dict[str, str]
    ml_prediction: str | None
    ml_confidence: float | None
    hf_prediction: str | None
    hf_confidence: float | None


class UrlAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(..., min_length=1, max_length=2048)
    fetch_content: bool = True


class UrlModelResponse(BaseModel):
    available: bool
    prediction: str | None
    phishing_probability: float | None
    model: str | None
    error: str | None


class RedirectResponse(BaseModel):
    source: str
    destination: str
    status: int


class UrlAnalysisResponse(BaseModel):
    valid: bool
    success: bool
    url: str
    final_url: str
    error: str | None
    failure_category: str | None
    analysis_mode: str
    disclosure: str
    hostname: str | None
    title: str
    extracted_text: str
    indicators: list[str]
    warnings: list[str]
    status_code: int | None
    bytes_downloaded: int
    redirect_history: list[RedirectResponse]
    url_model: UrlModelResponse
    advertisement_analysis: AnalysisResponse | None


class ImageTextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(..., min_length=1, max_length=200_000)


class OcrResponse(BaseModel):
    text: str
    confidence: float | None
    error: str | None
    available: bool
    engine: str | None


class ImageOcrResponse(BaseModel):
    valid: bool
    error: str | None
    file_size_kb: float
    dimensions: list[int]
    ocr: OcrResponse


class DocumentTextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(..., min_length=1, max_length=200_000)


class DocumentExtractionResponse(BaseModel):
    valid: bool
    source_type: str
    text: str
    error: str | None
    warnings: list[str]
    metadata: dict[str, int | float | bool]


class CsvRowResponse(BaseModel):
    row_index: int
    original_text: str
    final_verdict: str | None
    final_score: int | float | None
    risk_score: int | float | None
    risk_level: str | None
    rule_score: int | float | None
    rule_level: str | None
    matched_categories: str
    tfidf_status: str | None
    distilbert_status: str | None
    recommendation: str
    investigation_status: str | None
    review_required: bool | str | None
    validation_status: str
    ground_truth: str | None


class CsvSummaryResponse(BaseModel):
    total_rows: int
    successful_rows: int
    invalid_rows: int
    failed_rows: int
    skipped_rows: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    unscored_count: int


class CsvBatchResponse(BaseModel):
    valid: bool
    error: str | None
    columns: list[str]
    row_count: int
    text_column: str | None
    label_column: str | None
    results: list[CsvRowResponse]
    summary: CsvSummaryResponse
    export_csv: str | None


def analysis_response_from_result(result: dict[str, Any]) -> AnalysisResponse:
    """Convert the existing service result into the API-safe response shape."""

    raw_engine_status = result.get("engine_status") or {}
    engine_status = {
        str(name): str(status)
        for name, status in raw_engine_status.items()
        if status is not None
    }

    return AnalysisResponse(
        source_type=str(result.get("source_type") or "Direct Text"),
        extraction_status=str(result.get("extraction_status") or "unknown"),
        has_sufficient_evidence=bool(result.get("has_sufficient_evidence", False)),
        final_verdict=str(result.get("final_verdict") or "UNKNOWN"),
        final_score=result.get("final_score"),
        risk_score=result.get("risk_score"),
        risk_level=str(result.get("risk_level") or "UNKNOWN"),
        rule_score=result.get("rule_score"),
        rule_level=str(result.get("rule_level") or "UNKNOWN"),
        matched_categories=[str(item) for item in (result.get("matched_categories") or [])],
        evidence=[str(item) for item in (result.get("evidence") or [])],
        explanation=str(result.get("explanation") or ""),
        recommendation=str(result.get("recommendation") or ""),
        investigation_status=str(result.get("investigation_status") or ""),
        review_required=bool(result.get("review_required", False)),
        consensus_status=str(result.get("consensus_status") or ""),
        engine_status=engine_status,
        ml_prediction=result.get("ml_prediction"),
        ml_confidence=result.get("ml_confidence"),
        hf_prediction=result.get("hf_prediction"),
        hf_confidence=result.get("hf_confidence"),
    )
