import { FormEvent, useState } from "react"
import { analyzeText, AnalysisResponse, ApiError } from "../lib/api"

type AnalysisPageProps = {
  onBack: () => void
  onUnauthorized: () => void
}

function verdictTone(verdict: string): string {
  const value = verdict.toUpperCase()
  if (value.includes("CRITICAL")) return "border-rose-400/40 bg-rose-400/10 text-rose-200"
  if (value.includes("HIGH")) return "border-orange-400/40 bg-orange-400/10 text-orange-200"
  if (value.includes("MEDIUM")) return "border-amber-400/40 bg-amber-400/10 text-amber-200"
  return "border-emerald-400/40 bg-emerald-400/10 text-emerald-200"
}

export function AnalysisPage({ onBack, onUnauthorized }: AnalysisPageProps) {
  const [text, setText] = useState("")
  const [result, setResult] = useState<AnalysisResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const trimmed = text.trim()
    setError(null)
    setResult(null)
    if (!trimmed) {
      setError("Enter advertisement text before running analysis.")
      return
    }
    if (trimmed.length > 200_000) {
      setError("Advertisement text must be 200,000 characters or fewer.")
      return
    }
    setLoading(true)
    try {
      setResult(await analyzeText(trimmed))
    } catch (caught: unknown) {
      if (caught instanceof ApiError && caught.status === 401) {
        onUnauthorized()
        return
      }
      setError(caught instanceof Error ? caught.message : "Analysis service unavailable.")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-trace-ink text-slate-100">
      <header className="border-b border-trace-line/70 bg-trace-navy/80 px-5 py-5 sm:px-8">
        <div className="mx-auto flex max-w-[1200px] items-center justify-between gap-4">
          <div><p className="text-sm font-semibold tracking-[0.2em] text-trace-cyan">TRACE//FIN</p><p className="mt-1 text-xs uppercase tracking-[0.16em] text-trace-muted">Advertisement analysis</p></div>
          <button className="rounded-lg border border-trace-line px-3 py-2 text-xs text-slate-300 transition hover:border-trace-cyan hover:text-trace-cyan" onClick={onBack} type="button">Back to dashboard</button>
        </div>
      </header>

      <main className="mx-auto max-w-[1200px] px-5 py-8 sm:px-8 lg:py-10">
        <div className="mb-8"><p className="text-xs font-semibold uppercase tracking-[0.2em] text-trace-gold">Text intake</p><h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-50">Analyze an advertisement</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-trace-muted">Submit text for the existing unified analysis service. Results are evaluated live and are not saved by this API route.</p></div>
        <form className="rounded-xl border border-trace-line bg-trace-navy/70 p-5 sm:p-6" onSubmit={submit}>
          <label className="block text-sm font-medium text-slate-200" htmlFor="advertisement-text">Advertisement content</label>
          <textarea className="mt-3 min-h-52 w-full resize-y rounded-lg border border-trace-line bg-trace-ink/80 px-4 py-3 text-sm leading-6 text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-trace-cyan focus:ring-2 focus:ring-trace-cyan/20" id="advertisement-text" maxLength={200000} onChange={(event) => setText(event.target.value)} placeholder="Paste an advertisement, message, or financial offer for review…" value={text} />
          <div className="mt-3 flex flex-col justify-between gap-3 sm:flex-row sm:items-center"><span className="text-xs text-trace-muted">{text.length.toLocaleString()} / 200,000 characters</span><button className="rounded-lg bg-trace-cyan px-5 py-3 text-sm font-semibold text-trace-ink transition hover:bg-[#62e6dd] focus:outline-none focus:ring-2 focus:ring-trace-cyan disabled:cursor-wait disabled:opacity-60" disabled={loading} type="submit">{loading ? "Analyzing…" : "Run analysis"}</button></div>
          {error && <p className="mt-4 rounded-lg border border-rose-400/30 bg-rose-400/10 px-3 py-2.5 text-sm text-rose-200" role="alert">{error}</p>}
        </form>

        {result && <section className="mt-6 space-y-6" aria-live="polite">
          <div className={`rounded-xl border p-5 ${verdictTone(result.final_verdict)}`}><div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center"><div><p className="text-xs font-semibold uppercase tracking-[0.16em]">Final verdict</p><p className="mt-2 text-3xl font-semibold">{result.final_verdict}</p></div><div className="sm:text-right"><p className="text-xs uppercase tracking-[0.14em] opacity-75">Risk score</p><p className="mt-1 text-3xl font-semibold">{result.final_score ?? "Unavailable"}</p></div></div></div>
          <div className="grid gap-6 lg:grid-cols-2">
            <section className="rounded-xl border border-trace-line bg-trace-navy/65 p-5"><h2 className="text-sm font-semibold text-slate-200">Assessment</h2><p className="mt-4 text-sm leading-7 text-slate-300">{result.explanation}</p><div className="mt-5 rounded-lg border border-trace-line/70 bg-trace-ink/40 p-4"><p className="text-xs uppercase tracking-[0.14em] text-trace-muted">Recommendation</p><p className="mt-2 text-sm leading-6 text-slate-300">{result.recommendation}</p></div></section>
            <section className="rounded-xl border border-trace-line bg-trace-navy/65 p-5"><h2 className="text-sm font-semibold text-slate-200">Engine status</h2><div className="mt-4 space-y-3">{Object.entries(result.engine_status).map(([engine, status]) => <div className="flex items-center justify-between border-b border-trace-line/60 pb-3 text-sm last:border-0 last:pb-0" key={engine}><span className="text-slate-400">{engine}</span><span className={status === "available" ? "text-emerald-300" : "text-amber-300"}>{status}</span></div>)}</div><div className="mt-5 grid grid-cols-2 gap-3 text-sm"><div className="rounded-lg border border-trace-line/70 p-3"><p className="text-xs text-trace-muted">Rule score</p><p className="mt-1 text-slate-200">{result.rule_score ?? "Unavailable"}</p></div><div className="rounded-lg border border-trace-line/70 p-3"><p className="text-xs text-trace-muted">Review status</p><p className="mt-1 text-slate-200">{result.investigation_status}</p></div></div></section>
          </div>
          <div className="rounded-xl border border-trace-line bg-trace-navy/65 p-5"><div className="flex flex-wrap items-center justify-between gap-3"><h2 className="text-sm font-semibold text-slate-200">Signals and model outputs</h2><span className="text-xs text-trace-muted">{result.consensus_status}</span></div>{result.matched_categories.length > 0 ? <div className="mt-4 flex flex-wrap gap-2">{result.matched_categories.map((category) => <span className="rounded-full border border-trace-cyan/25 bg-trace-cyan/10 px-3 py-1.5 text-xs text-trace-cyan" key={category}>{category}</span>)}</div> : <p className="mt-4 text-sm text-trace-muted">No matched threat categories were reported.</p>}<p className="mt-4 text-xs text-trace-muted">Unavailable model outputs remain unavailable; no substitute score is displayed.</p></div>
        </section>}
      </main>
    </div>
  )
}
