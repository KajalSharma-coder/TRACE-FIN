import { FormEvent, useState } from "react"
import { analyzeUrl, ApiError, UrlAnalysisResponse } from "../lib/api"

type UrlAnalysisPageProps = {
  onBack: () => void
  onUnauthorized: () => void
}

export function UrlAnalysisPage({ onBack, onUnauthorized }: UrlAnalysisPageProps) {
  const [url, setUrl] = useState("")
  const [fetchContent, setFetchContent] = useState(true)
  const [result, setResult] = useState<UrlAnalysisResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const trimmed = url.trim()
    setError(null)
    setResult(null)
    if (!trimmed) {
      setError("Enter an HTTP or HTTPS URL before running analysis.")
      return
    }
    try {
      const parsed = new URL(trimmed)
      if (!(["http:", "https:"] as string[]).includes(parsed.protocol)) throw new Error("Only HTTP and HTTPS URLs are permitted.")
    } catch (caught: unknown) {
      setError(caught instanceof Error && caught.message !== "Invalid URL" ? caught.message : "Enter a valid HTTP or HTTPS URL.")
      return
    }
    setLoading(true)
    try {
      setResult(await analyzeUrl(trimmed, fetchContent))
    } catch (caught: unknown) {
      if (caught instanceof ApiError && caught.status === 401) {
        onUnauthorized()
        return
      }
      setError(caught instanceof Error ? caught.message : "URL analysis service unavailable.")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-trace-ink text-slate-100">
      <header className="border-b border-trace-line/70 bg-trace-navy/80 px-5 py-5 sm:px-8"><div className="mx-auto flex max-w-[1200px] items-center justify-between gap-4"><div><p className="text-sm font-semibold tracking-[0.2em] text-trace-cyan">TRACE//FIN</p><p className="mt-1 text-xs uppercase tracking-[0.16em] text-trace-muted">URL analysis</p></div><div className="flex gap-2"><button className="rounded-lg border border-trace-line px-3 py-2 text-xs text-slate-300 hover:border-trace-cyan hover:text-trace-cyan" onClick={onBack} type="button">Dashboard</button></div></div></header>
      <main className="mx-auto max-w-[1200px] px-5 py-8 sm:px-8 lg:py-10">
        <div className="mb-8"><p className="text-xs font-semibold uppercase tracking-[0.2em] text-trace-gold">Protected retrieval</p><h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-50">Inspect a suspicious URL</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-trace-muted">The backend performs validation, DNS checks, SSRF protection, redirect revalidation, timeout enforcement, size limits, and safe text extraction. The browser never contacts the submitted URL.</p></div>
        <form className="rounded-xl border border-trace-line bg-trace-navy/70 p-5 sm:p-6" onSubmit={submit}><label className="block text-sm font-medium text-slate-200" htmlFor="analysis-url">Website URL</label><input className="mt-3 w-full rounded-lg border border-trace-line bg-trace-ink/80 px-4 py-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-trace-cyan focus:ring-2 focus:ring-trace-cyan/20" id="analysis-url" onChange={(event) => setUrl(event.target.value)} placeholder="https://example-financial-offer.com/account-sales" type="url" value={url} /><label className="mt-4 flex items-center gap-3 text-sm text-slate-300"><input checked={fetchContent} className="h-4 w-4 accent-cyan-400" onChange={(event) => setFetchContent(event.target.checked)} type="checkbox" />Retrieve live content through the protected backend</label><div className="mt-5 flex justify-end"><button className="rounded-lg bg-trace-cyan px-5 py-3 text-sm font-semibold text-trace-ink transition hover:bg-[#62e6dd] disabled:cursor-wait disabled:opacity-60" disabled={loading} type="submit">{loading ? "Inspecting…" : "Analyze URL"}</button></div>{error && <p className="mt-4 rounded-lg border border-rose-400/30 bg-rose-400/10 px-3 py-2.5 text-sm text-rose-200" role="alert">{error}</p>}</form>
        {result && <section className="mt-6 space-y-6" aria-live="polite"><div className="rounded-xl border border-trace-line bg-trace-navy/65 p-5"><div className="flex flex-col justify-between gap-3 sm:flex-row"><div><p className="text-xs uppercase tracking-[0.14em] text-trace-muted">Analysis mode</p><p className="mt-2 text-xl font-semibold text-trace-cyan">{result.analysis_mode === "live_fetch" ? "Live content retrieved" : result.analysis_mode === "syntax_only" ? "Syntax only" : "Fetch failed"}</p></div><div className="sm:text-right"><p className="text-xs uppercase tracking-[0.14em] text-trace-muted">URL model · supplementary</p><p className="mt-2 text-sm text-slate-200">{result.url_model.available ? `${result.url_model.prediction ?? "Classified"}${result.url_model.phishing_probability !== null ? ` · ${(result.url_model.phishing_probability * 100).toFixed(1)}%` : ""}` : "Unavailable"}</p></div></div><p className="mt-4 text-sm leading-6 text-slate-300">{result.disclosure}</p>{result.error && <p className="mt-3 rounded-lg border border-amber-400/30 bg-amber-400/10 px-3 py-2.5 text-sm text-amber-200">{result.error}</p>}</div><div className="rounded-xl border border-trace-line bg-trace-navy/65 p-5"><div className="flex items-center justify-between gap-3"><div><p className="text-xs uppercase tracking-[0.14em] text-trace-muted">Financial advertisement verdict</p><p className="mt-2 text-3xl font-semibold text-slate-50">{result.advertisement_analysis?.final_verdict ?? "Unavailable"}</p></div><div className="text-right"><p className="text-xs uppercase tracking-[0.14em] text-trace-muted">Overall risk score</p><p className="mt-1 text-3xl font-semibold text-trace-cyan">{result.advertisement_analysis?.final_score ?? "Unavailable"}</p></div></div>{(!result.advertisement_analysis || result.advertisement_analysis.final_score === null) && <p className="mt-3 rounded-lg border border-amber-400/30 bg-amber-400/10 px-3 py-2.5 text-sm text-amber-200" role="alert">Financial advertisement risk score is unavailable: {result.advertisement_analysis ? "the content did not produce sufficient evidence for scoring." : "no content was available for analysis."}</p>}{result.advertisement_analysis && <p className="mt-3 text-sm leading-6 text-slate-300">{result.advertisement_analysis.explanation}</p>}</div><div className="grid gap-6 lg:grid-cols-2"><section className="rounded-xl border border-trace-line bg-trace-navy/65 p-5"><h2 className="text-sm font-semibold text-slate-200">URL findings</h2>{result.indicators.length > 0 ? <ul className="mt-4 space-y-2 text-sm leading-6 text-slate-300">{result.indicators.map((indicator) => <li key={indicator}>• {indicator}</li>)}</ul> : <p className="mt-4 text-sm text-trace-muted">No additional URL indicators were reported.</p>}<div className="mt-5 grid grid-cols-2 gap-3 text-sm"><div className="rounded-lg border border-trace-line/70 p-3"><p className="text-xs text-trace-muted">HTTP status</p><p className="mt-1 text-slate-200">{result.status_code ?? "Not fetched"}</p></div><div className="rounded-lg border border-trace-line/70 p-3"><p className="text-xs text-trace-muted">Bytes read</p><p className="mt-1 text-slate-200">{result.bytes_downloaded.toLocaleString()}</p></div></div></section><section className="rounded-xl border border-trace-line bg-trace-navy/65 p-5"><h2 className="text-sm font-semibold text-slate-200">Redirects and warnings</h2>{result.redirect_history.length > 0 ? <div className="mt-4 space-y-2 text-xs text-slate-400">{result.redirect_history.map((hop) => <p key={`${hop.source}-${hop.destination}-${hop.status}`}>{hop.status}: {hop.source} → {hop.destination}</p>)}</div> : <p className="mt-4 text-sm text-trace-muted">No redirects were followed.</p>}{result.warnings.map((warning) => <p className="mt-3 text-sm text-amber-200" key={warning}>{warning}</p>)}</section></div>{result.advertisement_analysis && (result.advertisement_analysis.matched_categories.length > 0 || result.advertisement_analysis.evidence.length > 0) && <section className="rounded-xl border border-trace-line bg-trace-navy/65 p-5"><h2 className="text-sm font-semibold text-slate-200">Financial-ad indicators</h2>{result.advertisement_analysis.matched_categories.length > 0 && <p className="mt-3 text-sm text-amber-200">{result.advertisement_analysis.matched_categories.join(" · ")}</p>}{result.advertisement_analysis.evidence.length > 0 && <ul className="mt-3 list-disc space-y-2 pl-5 text-sm leading-6 text-slate-300">{result.advertisement_analysis.evidence.map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}</ul>}</section>}{result.extracted_text && <section className="rounded-xl border border-trace-line bg-trace-navy/65 p-5"><h2 className="text-sm font-semibold text-slate-200">Sanitized extracted text</h2><p className="mt-4 max-h-64 overflow-auto whitespace-pre-wrap text-sm leading-6 text-slate-300">{result.extracted_text}</p></section>}</section>}
      </main>
    </div>
  )
}
