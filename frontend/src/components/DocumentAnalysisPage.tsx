import { ChangeEvent, FormEvent, useState } from "react"
import { AnalysisResponse, analyzeDocxText, analyzePdfText, ApiError, DocumentExtractionResponse, extractDocx, extractPdf } from "../lib/api"

type DocumentKind = "pdf" | "docx"
type DocumentAnalysisPageProps = { kind: DocumentKind; onBack: () => void; onUnauthorized: () => void }

function verdictTone(verdict: string): string {
  const value = verdict.toUpperCase()
  if (value.includes("HIGH") || value.includes("CRITICAL")) return "border-rose-400/40 bg-rose-400/10 text-rose-200"
  if (value.includes("MEDIUM")) return "border-amber-400/40 bg-amber-400/10 text-amber-200"
  return "border-emerald-400/40 bg-emerald-400/10 text-emerald-200"
}

export function DocumentAnalysisPage({ kind, onBack, onUnauthorized }: DocumentAnalysisPageProps) {
  const [document, setDocument] = useState<DocumentExtractionResponse | null>(null)
  const [text, setText] = useState("")
  const [result, setResult] = useState<AnalysisResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const isPdf = kind === "pdf"
  const label = isPdf ? "PDF" : "DOCX"

  async function chooseFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    if (!file) return
    setDocument(null)
    setResult(null)
    setText("")
    setError(null)
    setLoading(true)
    try {
      const extracted = isPdf ? await extractPdf(file) : await extractDocx(file)
      setDocument(extracted)
      if (!extracted.valid || extracted.error) setError(extracted.error ?? `${label} extraction failed.`)
      else setText(extracted.text)
    } catch (caught: unknown) {
      if (caught instanceof ApiError && caught.status === 401) {
        onUnauthorized()
        return
      }
      setError(caught instanceof Error ? caught.message : `${label} extraction service unavailable.`)
    } finally {
      setLoading(false)
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!text.trim()) {
      setError(`Enter or correct extracted ${label} text before running analysis.`)
      return
    }
    setError(null)
    setResult(null)
    setAnalyzing(true)
    try {
      setResult(isPdf ? await analyzePdfText(text.trim()) : await analyzeDocxText(text.trim()))
    } catch (caught: unknown) {
      if (caught instanceof ApiError && caught.status === 401) {
        onUnauthorized()
        return
      }
      setError(caught instanceof Error ? caught.message : "Analysis service unavailable.")
    } finally {
      setAnalyzing(false)
    }
  }

  return <div className="min-h-screen bg-trace-ink text-slate-100"><header className="border-b border-trace-line/70 bg-trace-navy/80 px-5 py-5 sm:px-8"><div className="mx-auto flex max-w-[1200px] items-center justify-between gap-4"><div><p className="text-sm font-semibold tracking-[0.2em] text-trace-cyan">TRACE//FIN</p><p className="mt-1 text-xs uppercase tracking-[0.16em] text-trace-muted">{label} document analysis</p></div><button className="rounded-lg border border-trace-line px-3 py-2 text-xs text-slate-300 hover:border-trace-cyan hover:text-trace-cyan" onClick={onBack} type="button">Back to dashboard</button></div></header><main className="mx-auto max-w-[1200px] px-5 py-8 sm:px-8 lg:py-10"><div className="mb-8"><p className="text-xs font-semibold uppercase tracking-[0.2em] text-trace-gold">Document intake</p><h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-50">Extract and analyze a {label}</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-trace-muted">Documents are processed in backend memory. Review and edit the extracted text before submitting it to the existing financial-advertisement analysis service.</p></div><section className="rounded-xl border border-trace-line bg-trace-navy/70 p-5 sm:p-6"><label className="block text-sm font-medium text-slate-200" htmlFor="document-upload">Upload {label}</label><p className="mt-2 text-xs text-trace-muted">{isPdf ? "PDF · maximum 10 MB · extraction bounded to 30 pages and 200,000 characters" : "DOCX · maximum 10 MB · ZIP safety checks, 2,000 paragraphs, 1,000 table rows, 200,000 characters"}</p><input accept={isPdf ? ".pdf,application/pdf" : ".docx,application/vnd.openxmlformats-officedocument.wordprocessingml.document"} className="mt-4 block w-full rounded-lg border border-dashed border-trace-line bg-trace-ink/50 px-4 py-4 text-sm text-slate-300 file:mr-4 file:rounded-md file:border-0 file:bg-trace-cyan file:px-3 file:py-2 file:text-xs file:font-semibold file:text-trace-ink" id="document-upload" onChange={chooseFile} type="file" />{loading && <p className="mt-4 text-sm text-trace-cyan" role="status">Extracting document text…</p>}{document && <div className="mt-5 rounded-lg border border-trace-line/70 bg-trace-ink/40 p-4"><p className="text-sm font-medium text-slate-200">Extraction {document.valid && !document.error ? "completed" : "failed"}</p><div className="mt-3 flex flex-wrap gap-3 text-xs text-trace-muted">{Object.entries(document.metadata).map(([key, value]) => <span className="rounded-full border border-trace-line px-3 py-1.5" key={key}>{key.replaceAll("_", " ")} · {String(value)}</span>)}</div>{document.warnings.map((warning) => <p className="mt-3 text-sm text-amber-200" key={warning}>{warning}</p>)}</div>}</section><form className="mt-6 rounded-xl border border-trace-line bg-trace-navy/70 p-5 sm:p-6" onSubmit={submit}><label className="block text-sm font-medium text-slate-200" htmlFor="document-text">Review and edit extracted text</label><textarea className="mt-4 min-h-56 w-full resize-y rounded-lg border border-trace-line bg-trace-ink/80 px-4 py-3 text-sm leading-6 text-slate-100 outline-none focus:border-trace-cyan focus:ring-2 focus:ring-trace-cyan/20" id="document-text" maxLength={200000} onChange={(event) => setText(event.target.value)} placeholder={`Extracted ${label} text will appear here after upload…`} value={text} /><div className="mt-3 flex justify-between gap-3 text-xs text-trace-muted"><span>{text.length.toLocaleString()} / 200,000 characters</span><button className="rounded-lg bg-trace-cyan px-5 py-3 text-sm font-semibold text-trace-ink transition hover:bg-[#62e6dd] disabled:cursor-wait disabled:opacity-60" disabled={loading || analyzing} type="submit">{analyzing ? "Analyzing…" : `Analyze ${label} text`}</button></div>{error && <p className="mt-4 rounded-lg border border-rose-400/30 bg-rose-400/10 px-3 py-2.5 text-sm text-rose-200" role="alert">{error}</p>}</form>{result && <section className="mt-6 space-y-5" aria-live="polite"><div className={`rounded-xl border p-5 ${verdictTone(result.final_verdict)}`}><div className="flex items-center justify-between gap-3"><div><p className="text-xs uppercase tracking-[0.14em]">Final verdict</p><p className="mt-2 text-3xl font-semibold">{result.final_verdict}</p></div><div className="text-right"><p className="text-xs uppercase tracking-[0.14em]">Risk score</p><p className="mt-1 text-3xl font-semibold">{result.final_score ?? "Unavailable"}</p></div></div></div><div className="grid gap-5 lg:grid-cols-2"><section className="rounded-xl border border-trace-line bg-trace-navy/65 p-5"><h2 className="text-sm font-semibold">Assessment</h2><p className="mt-4 text-sm leading-7 text-slate-300">{result.explanation}</p><p className="mt-4 text-sm leading-7 text-slate-300"><span className="text-xs uppercase tracking-[0.12em] text-trace-muted">Recommendation · </span>{result.recommendation}</p></section><section className="rounded-xl border border-trace-line bg-trace-navy/65 p-5"><h2 className="text-sm font-semibold">Model availability</h2><div className="mt-4 space-y-3">{Object.entries(result.engine_status).map(([engine, status]) => <div className="flex justify-between border-b border-trace-line/60 pb-3 text-sm last:border-0" key={engine}><span className="text-slate-400">{engine}</span><span className={status === "available" ? "text-emerald-300" : "text-amber-300"}>{status}</span></div>)}</div></section></div>{(result.matched_categories.length > 0 || result.evidence.length > 0) && <section className="rounded-xl border border-trace-line bg-trace-navy/65 p-5"><h2 className="text-sm font-semibold">Detected indicators</h2>{result.matched_categories.length > 0 && <p className="mt-3 text-sm text-amber-200">{result.matched_categories.join(" · ")}</p>}{result.evidence.length > 0 && <ul className="mt-3 list-disc space-y-2 pl-5 text-sm leading-6 text-slate-300">{result.evidence.map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}</ul>}</section>}</section>}</main></div>
}
