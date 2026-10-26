const configuredApiUrl = import.meta.env.VITE_TRACEFIN_API_URL?.trim()

/**
 * Empty means same-origin, which is served through the Vite /api proxy locally.
 * A deployment can provide VITE_TRACEFIN_API_URL without putting credentials
 * or environment-specific URLs in the bundle source.
 */
export const API_BASE_URL = configuredApiUrl?.replace(/\/$/, "") ?? ""

export type HealthState = "checking" | "online" | "offline"

export type HealthResponse = {
  status: string
  service: string
}

export type AuthUser = {
  id: number
  name: string
  email: string
}

export type AuthResponse = {
  user: AuthUser
}

export type DashboardRecentRecord = {
  record_id: string
  advertisement: string
  risk_score: number | null
  risk_level: string
  status: string
  submitted_at: string
}

export type DashboardResponse = {
  total: number
  risk_counts: Record<string, number>
  status_counts: Record<string, number>
  activity: Array<{ date: string; count: number }>
  category_counts: Record<string, number>
  recent: DashboardRecentRecord[]
  demo_count: number
}

export type InvestigationSummary = {
  record_id: string
  advertisement: string
  risk_score: number | null
  risk_level: string
  status: string
  submitted_at: string
  analysis_mode: string
  review_required: boolean
  review_recommendation: string
}

export type InvestigationListResponse = {
  items: InvestigationSummary[]
  count: number
  query: string
  risk_level: string | null
  status: string | null
}

export type InvestigationDetailResponse = InvestigationSummary & {
  ad_text: string
  matched_categories: string[]
  urls: string[]
  emails: string[]
  phone_numbers: string[]
  payment_identifiers: string[]
  ml_prediction: string | null
  ml_confidence: number | null
  hf_prediction: string | null
  hf_confidence: number | null
}

export type EvidenceNode = {
  id: string
  type: string
  label: string
  value: string
  source: string
  reason: string
  risk: string
  confidence: number | null
  related_ids: string[]
}

export type EvidenceGraphResponse = {
  record_id: string
  submitted_at: string
  analysis_mode: string
  central_id: string
  classification: string
  risk_score: number | null
  evidence_count: number
  high_risk_count: number
  nodes: EvidenceNode[]
  edges: Array<{ source: string; target: string; label: string }>
}

export type ReportRecord = {
  record_id: string
  advertisement_text: string
  risk_score: number | null
  risk_level: string
  ml_prediction: string | null
  ml_confidence: number | null
  review_required: boolean
  review_recommendation: string
  matched_categories: string
  extracted_urls: string
  extracted_emails: string
  extracted_phone_numbers: string
  extracted_payment_ids: string
  investigation_status: string
  analysis_mode: string
  is_synthetic: boolean
  submitted_at: string
}

export type ReportResponse = {
  filters: Record<string, string | number | null>
  summary: { total_matching: number; returned: number; truncated: boolean; risk_counts: Record<string, number>; status_counts: Record<string, number> }
  records: ReportRecord[]
  export_csv: string | null
}

export type AnalysisResponse = {
  source_type: string
  extraction_status: string
  has_sufficient_evidence: boolean
  final_verdict: string
  final_score: number | null
  risk_score: number | null
  risk_level: string
  rule_score: number | null
  rule_level: string
  matched_categories: string[]
  evidence: string[]
  explanation: string
  recommendation: string
  investigation_status: string
  review_required: boolean
  consensus_status: string
  engine_status: Record<string, string>
  ml_prediction: string | null
  ml_confidence: number | null
  hf_prediction: string | null
  hf_confidence: number | null
}

export type UrlModelResponse = {
  available: boolean
  prediction: string | null
  phishing_probability: number | null
  model: string | null
  error: string | null
}

export type RedirectResponse = {
  source: string
  destination: string
  status: number
}

export type UrlAnalysisResponse = {
  valid: boolean
  success: boolean
  url: string
  final_url: string
  error: string | null
  failure_category: string | null
  analysis_mode: string
  disclosure: string
  hostname: string | null
  title: string
  extracted_text: string
  indicators: string[]
  warnings: string[]
  status_code: number | null
  bytes_downloaded: number
  redirect_history: RedirectResponse[]
  url_model: UrlModelResponse
  advertisement_analysis: AnalysisResponse | null
}

export type OcrResponse = {
  text: string
  confidence: number | null
  error: string | null
  available: boolean
  engine: string | null
}

export type ImageOcrResponse = {
  valid: boolean
  error: string | null
  file_size_kb: number
  dimensions: number[]
  ocr: OcrResponse
}

export type DocumentExtractionResponse = {
  valid: boolean
  source_type: string
  text: string
  error: string | null
  warnings: string[]
  metadata: Record<string, number | boolean>
}

export type CsvRowResponse = {
  row_index: number
  original_text: string
  final_verdict: string | null
  final_score: number | null
  risk_score: number | null
  risk_level: string | null
  rule_score: number | null
  rule_level: string | null
  matched_categories: string
  tfidf_status: string | null
  distilbert_status: string | null
  recommendation: string
  investigation_status: string | null
  review_required: boolean | string | null
  validation_status: string
  ground_truth: string | null
}

export type CsvBatchResponse = {
  valid: boolean
  error: string | null
  columns: string[]
  row_count: number
  text_column: string | null
  label_column: string | null
  results: CsvRowResponse[]
  summary: {
    total_rows: number
    successful_rows: number
    invalid_rows: number
    failed_rows: number
    skipped_rows: number
    critical_count: number
    high_count: number
    medium_count: number
    low_count: number
    unscored_count: number
  }
  export_csv: string | null
}

type CsrfResponse = {
  csrf_token: string
}

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message)
    this.name = "ApiError"
  }
}

export async function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE_URL}/api/health`, {
    method: "GET",
    headers: { Accept: "application/json" },
    signal,
  })

  if (!response.ok) {
    throw new Error(`Health check failed (${response.status})`)
  }

  return response.json() as Promise<HealthResponse>
}

async function responseError(response: Response, fallback: string): Promise<ApiError> {
  try {
    const body = (await response.json()) as { detail?: unknown }
    if (typeof body.detail === "string" && body.detail) return new ApiError(body.detail, response.status)
  } catch {
    // Keep the user-facing error generic when the server response is not JSON.
  }
  return new ApiError(fallback, response.status)
}

export async function getCsrfToken(): Promise<string> {
  const response = await fetch(`${API_BASE_URL}/api/auth/csrf`, {
    credentials: "include",
    headers: { Accept: "application/json" },
  })
  if (!response.ok) throw await responseError(response, "Unable to prepare secure sign-in.")
  const body = (await response.json()) as CsrfResponse
  if (!body.csrf_token) throw new Error("Unable to prepare secure sign-in.")
  return body.csrf_token
}

export async function login(email: string, password: string): Promise<AuthUser> {
  const csrfToken = await getCsrfToken()
  const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
    method: "POST",
    credentials: "include",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken,
    },
    body: JSON.stringify({ email, password }),
  })
  if (!response.ok) throw await responseError(response, "Sign-in failed. Please try again.")
  const body = (await response.json()) as AuthResponse
  return body.user
}

export async function register(name: string, email: string, password: string, confirmation: string): Promise<AuthUser> {
  const csrfToken = await getCsrfToken()
  const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
    method: "POST",
    credentials: "include",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken,
    },
    body: JSON.stringify({ name, email, password, confirmation }),
  })
  if (!response.ok) throw await responseError(response, "Account creation failed. Please try again.")
  const body = (await response.json()) as AuthResponse
  return body.user
}

export async function getCurrentSession(): Promise<AuthUser | null> {
  const response = await fetch(`${API_BASE_URL}/api/auth/session`, {
    credentials: "include",
    headers: { Accept: "application/json" },
  })
  if (response.status === 401) return null
  if (!response.ok) throw await responseError(response, "Unable to verify the current session.")
  return ((await response.json()) as AuthResponse).user
}

export async function getDashboard(): Promise<DashboardResponse> {
  const response = await fetch(`${API_BASE_URL}/api/dashboard`, {
    credentials: "include",
    headers: { Accept: "application/json" },
  })
  if (!response.ok) throw await responseError(response, "Unable to load dashboard data.")
  return (await response.json()) as DashboardResponse
}

export async function logout(): Promise<void> {
  const csrfToken = await getCsrfToken()
  const response = await fetch(`${API_BASE_URL}/api/auth/logout`, {
    method: "POST",
    credentials: "include",
    headers: { Accept: "application/json", "X-CSRF-Token": csrfToken },
  })
  if (!response.ok) throw await responseError(response, "Unable to sign out securely.")
}

export async function analyzeText(text: string): Promise<AnalysisResponse> {
  const csrfToken = await getCsrfToken()
  const response = await fetch(`${API_BASE_URL}/api/analyze`, {
    method: "POST",
    credentials: "include",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken,
    },
    body: JSON.stringify({ text }),
  })
  if (!response.ok) throw await responseError(response, "Analysis service unavailable.")
  return (await response.json()) as AnalysisResponse
}

export async function analyzeUrl(url: string, fetchContent: boolean): Promise<UrlAnalysisResponse> {
  const csrfToken = await getCsrfToken()
  const response = await fetch(`${API_BASE_URL}/api/analyze-url`, {
    method: "POST",
    credentials: "include",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken,
    },
    body: JSON.stringify({ url, fetch_content: fetchContent }),
  })
  if (!response.ok) throw await responseError(response, "URL analysis service unavailable.")
  return (await response.json()) as UrlAnalysisResponse
}

export async function extractImageText(file: File): Promise<ImageOcrResponse> {
  const csrfToken = await getCsrfToken()
  const form = new FormData()
  form.append("image", file)
  const response = await fetch(`${API_BASE_URL}/api/image-ocr`, {
    method: "POST",
    credentials: "include",
    headers: { Accept: "application/json", "X-CSRF-Token": csrfToken },
    body: form,
  })
  if (!response.ok) throw await responseError(response, "Image OCR service unavailable.")
  return (await response.json()) as ImageOcrResponse
}

export async function analyzeImageText(text: string): Promise<AnalysisResponse> {
  const csrfToken = await getCsrfToken()
  const response = await fetch(`${API_BASE_URL}/api/analyze-image-text`, {
    method: "POST",
    credentials: "include",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken,
    },
    body: JSON.stringify({ text }),
  })
  if (!response.ok) throw await responseError(response, "Analysis service unavailable.")
  return (await response.json()) as AnalysisResponse
}

async function extractDocument(file: File, endpoint: string): Promise<DocumentExtractionResponse> {
  const csrfToken = await getCsrfToken()
  const form = new FormData()
  form.append("document", file)
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    method: "POST",
    credentials: "include",
    headers: { Accept: "application/json", "X-CSRF-Token": csrfToken },
    body: form,
  })
  if (!response.ok) throw await responseError(response, "Document extraction service unavailable.")
  return (await response.json()) as DocumentExtractionResponse
}

export function extractPdf(file: File): Promise<DocumentExtractionResponse> {
  return extractDocument(file, "/api/document/pdf")
}

export function extractDocx(file: File): Promise<DocumentExtractionResponse> {
  return extractDocument(file, "/api/document/docx")
}

async function analyzeDocumentText(text: string, endpoint: string): Promise<AnalysisResponse> {
  const csrfToken = await getCsrfToken()
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    method: "POST",
    credentials: "include",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken,
    },
    body: JSON.stringify({ text }),
  })
  if (!response.ok) throw await responseError(response, "Analysis service unavailable.")
  return (await response.json()) as AnalysisResponse
}

export function analyzePdfText(text: string): Promise<AnalysisResponse> {
  return analyzeDocumentText(text, "/api/analyze-pdf-text")
}

export function analyzeDocxText(text: string): Promise<AnalysisResponse> {
  return analyzeDocumentText(text, "/api/analyze-docx-text")
}

export async function analyzeCsv(file: File, textColumn: string | null, labelColumn: string | null, includeHf: boolean): Promise<CsvBatchResponse> {
  const csrfToken = await getCsrfToken()
  const form = new FormData()
  form.append("csv_file", file)
  if (textColumn) form.append("text_column", textColumn)
  if (labelColumn) form.append("label_column", labelColumn)
  form.append("include_hf", String(includeHf))
  const response = await fetch(`${API_BASE_URL}/api/analyze-csv`, {
    method: "POST",
    credentials: "include",
    headers: { Accept: "application/json", "X-CSRF-Token": csrfToken },
    body: form,
  })
  if (!response.ok) throw await responseError(response, "CSV analysis service unavailable.")
  return (await response.json()) as CsvBatchResponse
}

export async function getInvestigations(query = "", riskLevel: string | null = null, status: string | null = null): Promise<InvestigationListResponse> {
  const params = new URLSearchParams()
  if (query.trim()) params.set("query", query.trim())
  if (riskLevel) params.set("risk_level", riskLevel)
  if (status) params.set("status", status)
  const suffix = params.toString() ? `?${params.toString()}` : ""
  const response = await fetch(`${API_BASE_URL}/api/investigations${suffix}`, { credentials: "include", headers: { Accept: "application/json" } })
  if (!response.ok) throw await responseError(response, "Investigation data unavailable.")
  return (await response.json()) as InvestigationListResponse
}

export async function getInvestigation(recordId: string): Promise<InvestigationDetailResponse> {
  const response = await fetch(`${API_BASE_URL}/api/investigations/${encodeURIComponent(recordId)}`, { credentials: "include", headers: { Accept: "application/json" } })
  if (!response.ok) throw await responseError(response, "Investigation data unavailable.")
  return (await response.json()) as InvestigationDetailResponse
}

export async function updateInvestigationStatus(recordId: string, status: string): Promise<InvestigationDetailResponse> {
  const csrfToken = await getCsrfToken()
  const response = await fetch(`${API_BASE_URL}/api/investigations/${encodeURIComponent(recordId)}/status`, {
    method: "PATCH",
    credentials: "include",
    headers: { Accept: "application/json", "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
    body: JSON.stringify({ status }),
  })
  if (!response.ok) throw await responseError(response, "Investigation status could not be updated.")
  return (await response.json()) as InvestigationDetailResponse
}

export async function getEvidenceGraph(recordId: string): Promise<EvidenceGraphResponse> {
  const response = await fetch(`${API_BASE_URL}/api/evidence/${encodeURIComponent(recordId)}`, { credentials: "include", headers: { Accept: "application/json" } })
  if (!response.ok) throw await responseError(response, "Evidence data unavailable.")
  return (await response.json()) as EvidenceGraphResponse
}

export async function getRecordsReport(query = "", riskLevel: string | null = null, status: string | null = null): Promise<ReportResponse> {
  const params = new URLSearchParams()
  if (query.trim()) params.set("query", query.trim())
  if (riskLevel) params.set("risk_level", riskLevel)
  if (status) params.set("status", status)
  const suffix = params.toString() ? `?${params.toString()}` : ""
  const response = await fetch(`${API_BASE_URL}/api/reports/records${suffix}`, { credentials: "include", headers: { Accept: "application/json" } })
  if (!response.ok) throw await responseError(response, "Report data unavailable.")
  return (await response.json()) as ReportResponse
}
