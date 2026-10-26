import { useEffect, useState } from "react"
import { ApiError, getInvestigation, getInvestigations, InvestigationDetailResponse, InvestigationSummary, updateInvestigationStatus } from "../lib/api"

type InvestigationsPageProps = { onBack: () => void; onUnauthorized: () => void; onUrlAnalyze: () => void }
const statuses = ["Open", "Reviewing", "Escalated", "Closed"]
const riskLevels = ["Critical", "High", "Medium", "Low"]

function InvestigationCard({ item, selected, onSelect }: { item: InvestigationSummary; selected: boolean; onSelect: () => void }) {
  return <button className={`w-full rounded-xl border p-4 text-left transition ${selected ? "border-trace-cyan/70 bg-trace-cyan/10" : "border-trace-line bg-trace-navy/65 hover:border-trace-cyan/40"}`} onClick={onSelect} type="button">
    <div className="flex items-start justify-between gap-3"><span className="font-mono text-xs text-trace-cyan">{item.record_id}</span><span className="text-xs text-slate-400">{item.status}</span></div>
    <p className="mt-3 line-clamp-2 text-sm leading-6 text-slate-200">{item.advertisement || "No advertisement text"}</p>
    <div className="mt-4 flex flex-wrap gap-3 text-xs text-trace-muted"><span>{item.risk_level}{item.risk_score !== null ? ` · ${item.risk_score}` : ""}</span><span>{item.submitted_at.replace("T", " ").slice(0, 16)}</span></div>
  </button>
}

function readableAnalysisMode(mode: string): string {
  const normalized = mode.replace(/_unified$/i, "").replace(/_/g, " ").replace(/\s+/g, " ").trim()
  return normalized.replace(/\b\w/g, (letter) => letter.toUpperCase()) || "Analysis"
}

function Detail({ detail, onStatus, onUrlAnalyze, updating }: { detail: InvestigationDetailResponse; onStatus: (status: string) => void; onUrlAnalyze: () => void; updating: boolean }) {
  const [pendingStatus, setPendingStatus] = useState(detail.status)
  useEffect(() => setPendingStatus(detail.status), [detail.status])
  return <section className="rounded-xl border border-trace-line bg-trace-navy/65 p-5 sm:p-6" aria-labelledby="case-detail-title">
    <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start"><div><p className="font-mono text-xs text-trace-cyan">{detail.record_id}</p><h2 id="case-detail-title" className="mt-2 text-xl font-semibold text-slate-50">Case dossier</h2></div><span className="rounded-full border border-trace-line px-3 py-1.5 text-xs text-slate-300">{detail.status}</span></div>
    <div className="mt-6 grid gap-3 sm:grid-cols-4"><div className="rounded-lg border border-trace-line/70 p-3"><p className="text-xs text-trace-muted">Risk score</p><p className="mt-1 text-lg text-slate-100">{detail.risk_score ?? "Unavailable"}</p></div><div className="rounded-lg border border-trace-line/70 p-3"><p className="text-xs text-trace-muted">Risk level</p><p className="mt-1 text-lg text-slate-100">{detail.risk_level}</p></div><div className="rounded-lg border border-trace-line/70 p-3"><p className="text-xs text-trace-muted">Analysis mode</p><p className="mt-1 text-sm text-slate-100">{readableAnalysisMode(detail.analysis_mode)}</p></div><div className="rounded-lg border border-trace-line/70 p-3"><p className="text-xs text-trace-muted">Review required</p><p className="mt-1 text-sm text-slate-100">{detail.review_required ? "Yes" : "No"}</p></div></div>
    <div className={`mt-6 rounded-lg border p-4 text-sm ${detail.review_required ? "border-trace-gold/30 bg-trace-gold/10 text-trace-gold" : "border-emerald-400/25 bg-emerald-400/5 text-emerald-200"}`}><p className="font-semibold">Recommended next step</p><p className="mt-2 leading-6">{detail.review_recommendation}</p>{detail.review_required && detail.analysis_mode.toLowerCase().includes("syntax_only") && <button className="mt-4 rounded-lg border border-trace-cyan/40 px-3 py-2 text-xs font-semibold text-trace-cyan transition hover:bg-trace-cyan/10 focus:outline-none focus:ring-2 focus:ring-trace-cyan/50" onClick={onUrlAnalyze} type="button">Inspect URL with live content</button>}</div>
    <div className="mt-6"><p className="text-xs uppercase tracking-[0.14em] text-trace-muted">Investigation status</p><div className="mt-3 flex flex-wrap items-center gap-3"><select className="rounded-lg border border-trace-line bg-trace-ink px-3 py-2.5 text-sm text-slate-100" disabled={updating} onChange={(event) => setPendingStatus(event.target.value)} value={pendingStatus}>{statuses.map((status) => <option key={status} value={status}>{status}</option>)}</select><button className="rounded-lg border border-trace-cyan/40 px-3 py-2.5 text-xs text-trace-cyan hover:bg-trace-cyan/10 disabled:cursor-not-allowed disabled:opacity-50" disabled={updating || pendingStatus === detail.status} onClick={() => onStatus(pendingStatus)} type="button">Apply status change</button>{updating && <span className="text-xs text-trace-cyan" role="status">Saving status…</span>}</div></div>
    <div className="mt-6"><p className="text-xs uppercase tracking-[0.14em] text-trace-muted">Original advertisement</p><p className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap rounded-lg border border-trace-line/70 bg-trace-ink/40 p-4 text-sm leading-6 text-slate-300">{detail.ad_text}</p></div>
    <div className="mt-6 grid gap-5 lg:grid-cols-2"><div><p className="text-xs uppercase tracking-[0.14em] text-trace-muted">Matched categories</p>{detail.matched_categories.length ? <ul className="mt-3 space-y-2 text-sm text-slate-300">{detail.matched_categories.map((item) => <li key={item}>• {item}</li>)}</ul> : <p className="mt-3 text-sm text-trace-muted">None detected.</p>}</div><div><p className="text-xs uppercase tracking-[0.14em] text-trace-muted">Model availability</p><div className="mt-3 space-y-2 text-sm text-slate-300"><p>TF-IDF: {detail.ml_prediction ?? "Unavailable"}</p><p>DistilBERT: {detail.hf_prediction ?? "Unavailable"}</p></div></div></div>
  </section>
}

export function InvestigationsPage({ onBack, onUnauthorized, onUrlAnalyze }: InvestigationsPageProps) {
  const [items, setItems] = useState<InvestigationSummary[]>([])
  const [selected, setSelected] = useState<InvestigationDetailResponse | null>(null)
  const [query, setQuery] = useState("")
  const [risk, setRisk] = useState("")
  const [status, setStatus] = useState("")
  const [loading, setLoading] = useState(true)
  const [updating, setUpdating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function loadCases() {
    setLoading(true); setError(null)
    try { const response = await getInvestigations(query, risk || null, status || null); setItems(response.items); if (selected && !response.items.some((item) => item.record_id === selected.record_id)) setSelected(null) }
    catch (caught: unknown) { if (caught instanceof ApiError && caught.status === 401) { onUnauthorized(); return }; setError(caught instanceof Error ? caught.message : "Investigation data unavailable.") }
    finally { setLoading(false) }
  }

  useEffect(() => { void loadCases() }, [risk, status])

  async function selectCase(recordId: string) {
    setError(null)
    try { setSelected(await getInvestigation(recordId)) }
    catch (caught: unknown) { if (caught instanceof ApiError && caught.status === 401) { onUnauthorized(); return }; setError(caught instanceof Error ? caught.message : "Investigation detail unavailable.") }
  }

  async function changeStatus(nextStatus: string) {
    if (!selected || nextStatus === selected.status) return
    setUpdating(true); setError(null)
    try { const updated = await updateInvestigationStatus(selected.record_id, nextStatus); setSelected(updated); await loadCases() }
    catch (caught: unknown) { if (caught instanceof ApiError && caught.status === 401) { onUnauthorized(); return }; setError(caught instanceof Error ? caught.message : "Investigation status could not be updated.") }
    finally { setUpdating(false) }
  }

  return <div className="min-h-screen bg-trace-ink text-slate-100"><header className="border-b border-trace-line/70 bg-trace-navy/80 px-5 py-5 sm:px-8"><div className="mx-auto flex max-w-[1500px] items-center justify-between gap-4"><div><p className="text-sm font-semibold tracking-[0.2em] text-trace-cyan">TRACE//FIN</p><p className="mt-1 text-xs uppercase tracking-[0.16em] text-trace-muted">Investigation cases</p></div><button className="rounded-lg border border-trace-line px-3 py-2 text-xs text-slate-300 hover:border-trace-cyan hover:text-trace-cyan" onClick={onBack} type="button">Back to dashboard</button></div></header><main className="mx-auto max-w-[1500px] px-5 py-8 sm:px-8 lg:py-10"><div className="mb-8"><p className="text-xs font-semibold uppercase tracking-[0.2em] text-trace-gold">Case management</p><h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-50">Investigations and case files</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-trace-muted">Review persisted investigator analyses and manage their existing lifecycle status. Evidence management remains in the Streamlit workspace.</p></div><section className="rounded-xl border border-trace-line bg-trace-navy/70 p-5"><form className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_180px_180px_auto]" onSubmit={(event) => { event.preventDefault(); void loadCases() }}><input className="rounded-lg border border-trace-line bg-trace-ink px-3 py-2.5 text-sm text-slate-100 placeholder:text-slate-600" maxLength={200} onChange={(event) => setQuery(event.target.value)} placeholder="Search record ID or advertisement text" value={query} /><select className="rounded-lg border border-trace-line bg-trace-ink px-3 py-2.5 text-sm text-slate-100" onChange={(event) => setRisk(event.target.value)} value={risk}><option value="">All risk levels</option>{riskLevels.map((level) => <option key={level} value={level}>{level}</option>)}</select><select className="rounded-lg border border-trace-line bg-trace-ink px-3 py-2.5 text-sm text-slate-100" onChange={(event) => setStatus(event.target.value)} value={status}><option value="">All statuses</option>{statuses.map((value) => <option key={value} value={value}>{value}</option>)}</select><button className="rounded-lg bg-trace-cyan px-4 py-2.5 text-sm font-semibold text-trace-ink hover:bg-[#62e6dd]" type="submit">Search</button></form></section>{error && <p className="mt-5 rounded-lg border border-rose-400/30 bg-rose-400/10 px-3 py-2.5 text-sm text-rose-200" role="alert">{error}</p>}{loading ? <p className="mt-6 text-sm text-trace-cyan" role="status">Loading investigation cases…</p> : <div className="mt-6 grid gap-6 xl:grid-cols-[380px_minmax(0,1fr)]"><section><p className="mb-3 text-xs uppercase tracking-[0.14em] text-trace-muted">{items.length} matching case{items.length === 1 ? "" : "s"}</p>{items.length ? <div className="space-y-3">{items.map((item) => <InvestigationCard item={item} key={item.record_id} onSelect={() => void selectCase(item.record_id)} selected={selected?.record_id === item.record_id} />)}</div> : <div className="rounded-xl border border-trace-line bg-trace-navy/50 p-5 text-sm text-trace-muted">No investigations match the active filters.</div>}</section>{selected ? <Detail detail={selected} onStatus={(nextStatus) => void changeStatus(nextStatus)} onUrlAnalyze={onUrlAnalyze} updating={updating} /> : <div className="grid min-h-64 place-items-center rounded-xl border border-dashed border-trace-line bg-trace-navy/35 p-6 text-center text-sm text-trace-muted">Select a case to inspect its dossier and lifecycle status.</div>}</div>}</main></div>
}
