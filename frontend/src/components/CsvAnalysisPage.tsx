import { ChangeEvent, useMemo, useState } from "react"
import { analyzeCsv, ApiError, CsvBatchResponse } from "../lib/api"

type CsvAnalysisPageProps = { onBack: () => void; onUnauthorized: () => void }

function downloadCsv(content: string) {
  const blob = new Blob([content], { type: "text/csv;charset=utf-8" })
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = "tracefin-batch-results.csv"
  link.click()
  URL.revokeObjectURL(url)
}

export function CsvAnalysisPage({ onBack, onUnauthorized }: CsvAnalysisPageProps) {
  const [file, setFile] = useState<File | null>(null)
  const [data, setData] = useState<CsvBatchResponse | null>(null)
  const [textColumn, setTextColumn] = useState("")
  const [labelColumn, setLabelColumn] = useState("")
  const [includeHf, setIncludeHf] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const suggestedText = useMemo(() => data?.columns.find((column) => /text|ad|message|body|content/i.test(column)) ?? data?.columns[0] ?? "", [data])
  const suggestedLabel = useMemo(() => data?.columns.find((column) => /risk|label|target|class/i.test(column)) ?? "", [data])

  async function chooseFile(event: ChangeEvent<HTMLInputElement>) {
    const selected = event.target.files?.[0] ?? null
    setFile(selected)
    setData(null)
    setError(null)
    setTextColumn("")
    setLabelColumn("")
    if (!selected) return
    setLoading(true)
    try {
      const result = await analyzeCsv(selected, null, null, false)
      setData(result)
      if (!result.valid) setError(result.error ?? "CSV validation failed.")
    } catch (caught: unknown) {
      if (caught instanceof ApiError && caught.status === 401) {
        onUnauthorized()
        return
      }
      setError(caught instanceof Error ? caught.message : "CSV validation service unavailable.")
    } finally {
      setLoading(false)
    }
  }

  async function runAnalysis() {
    if (!file) {
      setError("Choose a CSV file first.")
      return
    }
    const selectedText = textColumn || suggestedText
    if (!selectedText) {
      setError("Select the advertisement text column.")
      return
    }
    setError(null)
    setLoading(true)
    try {
      const result = await analyzeCsv(file, selectedText, labelColumn || suggestedLabel || null, includeHf)
      setData(result)
      if (!result.valid) setError(result.error ?? "CSV validation failed.")
    } catch (caught: unknown) {
      if (caught instanceof ApiError && caught.status === 401) {
        onUnauthorized()
        return
      }
      setError(caught instanceof Error ? caught.message : "CSV analysis service unavailable.")
    } finally {
      setLoading(false)
    }
  }

  return <div className="min-h-screen bg-trace-ink text-slate-100"><header className="border-b border-trace-line/70 bg-trace-navy/80 px-5 py-5 sm:px-8"><div className="mx-auto flex max-w-[1400px] items-center justify-between gap-4"><div><p className="text-sm font-semibold tracking-[0.2em] text-trace-cyan">TRACE//FIN</p><p className="mt-1 text-xs uppercase tracking-[0.16em] text-trace-muted">CSV batch analysis</p></div><button className="rounded-lg border border-trace-line px-3 py-2 text-xs text-slate-300 hover:border-trace-cyan hover:text-trace-cyan" onClick={onBack} type="button">Back to dashboard</button></div></header><main className="mx-auto max-w-[1400px] px-5 py-8 sm:px-8 lg:py-10"><div className="mb-8"><p className="text-xs font-semibold uppercase tracking-[0.2em] text-trace-gold">Bulk triage</p><h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-50">Analyze advertisement records in bulk</h1><p className="mt-2 text-sm leading-6 text-trace-muted">CSV files are processed in memory. UTF-8, UTF-8-SIG, Latin-1, and CP1252 encodings are supported; maximum 50 MB and 5,000 rows.</p></div><section className="rounded-xl border border-trace-line bg-trace-navy/70 p-5 sm:p-6"><label className="block text-sm font-medium text-slate-200" htmlFor="csv-upload">CSV dataset</label><input accept=".csv,text/csv" className="mt-4 block w-full rounded-lg border border-dashed border-trace-line bg-trace-ink/50 px-4 py-4 text-sm text-slate-300 file:mr-4 file:rounded-md file:border-0 file:bg-trace-cyan file:px-3 file:py-2 file:text-xs file:font-semibold file:text-trace-ink" id="csv-upload" onChange={chooseFile} type="file" />{file && <p className="mt-3 text-xs text-trace-muted">Selected: {file.name} · {(file.size / 1024 / 1024).toFixed(2)} MB</p>}{data?.columns.length ? <div className="mt-5 grid gap-4 md:grid-cols-2"><label className="text-sm text-slate-300">Advertisement text column<select className="mt-2 w-full rounded-lg border border-trace-line bg-trace-ink px-3 py-2.5 text-sm text-slate-100" onChange={(event) => setTextColumn(event.target.value)} value={textColumn || suggestedText}>{data.columns.map((column) => <option key={column} value={column}>{column}</option>)}</select></label><label className="text-sm text-slate-300">Ground-truth label column (optional)<select className="mt-2 w-full rounded-lg border border-trace-line bg-trace-ink px-3 py-2.5 text-sm text-slate-100" onChange={(event) => setLabelColumn(event.target.value)} value={labelColumn || suggestedLabel}><option value="">None</option>{data.columns.map((column) => <option key={column} value={column}>{column}</option>)}</select></label></div> : null}<label className="mt-4 flex items-center gap-3 text-sm text-slate-300"><input checked={includeHf} className="h-4 w-4 accent-cyan-400" onChange={(event) => setIncludeHf(event.target.checked)} type="checkbox" />Enable DistilBERT inference (slower)</label><div className="mt-5 flex justify-end"><button className="rounded-lg bg-trace-cyan px-5 py-3 text-sm font-semibold text-trace-ink transition hover:bg-[#62e6dd] disabled:cursor-wait disabled:opacity-60" disabled={loading || !file || !data?.columns.length} onClick={runAnalysis} type="button">{loading ? "Analyzing batch…" : "Run batch analysis"}</button></div>{loading && <p className="mt-4 text-sm text-trace-cyan" role="status">{data?.columns.length ? "Analyzing rows and collecting bounded results…" : "Validating CSV and reading columns…"}</p>}{error && <p className="mt-4 rounded-lg border border-rose-400/30 bg-rose-400/10 px-3 py-2.5 text-sm text-rose-200" role="alert">{error}</p>}</section>{data?.valid && data.results.length > 0 && <section className="mt-6 space-y-6"><div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">{[["Total", data.summary.total_rows], ["Successful", data.summary.successful_rows], ["Invalid", data.summary.invalid_rows], ["Failed", data.summary.failed_rows], ["High/Critical", data.summary.high_count + data.summary.critical_count]].map(([label, value]) => <div className="rounded-xl border border-trace-line bg-trace-navy/65 p-4" key={String(label)}><p className="text-xs uppercase tracking-[0.12em] text-trace-muted">{label}</p><p className="mt-2 text-2xl font-semibold text-trace-cyan">{value}</p></div>)}</div><div className="flex flex-wrap items-center justify-between gap-3"><p className="text-sm text-trace-muted">{data.summary.medium_count} medium · {data.summary.low_count} low · {data.summary.unscored_count} unscored</p>{data.export_csv && <button className="rounded-lg border border-trace-cyan/40 px-4 py-2.5 text-xs text-trace-cyan hover:bg-trace-cyan/10" onClick={() => downloadCsv(data.export_csv!)} type="button">Download sanitized CSV</button>}</div><div className="overflow-x-auto rounded-xl border border-trace-line bg-trace-navy/65"><table className="w-full min-w-[1000px] text-left text-sm"><thead className="border-b border-trace-line text-xs uppercase tracking-[0.1em] text-slate-500"><tr><th className="px-3 py-3">Row</th><th className="px-3 py-3">Advertisement</th><th className="px-3 py-3">Verdict</th><th className="px-3 py-3">Score</th><th className="px-3 py-3">Risk</th><th className="px-3 py-3">Models</th><th className="px-3 py-3">Validation</th></tr></thead><tbody>{data.results.map((row) => <tr className="border-b border-trace-line/60 last:border-0" key={row.row_index}><td className="px-3 py-3 font-mono text-xs text-trace-cyan">{row.row_index}</td><td className="max-w-[340px] truncate px-3 py-3 text-slate-300">{row.original_text || "—"}</td><td className="px-3 py-3 text-slate-200">{row.final_verdict ?? "—"}</td><td className="px-3 py-3 text-slate-300">{row.final_score ?? "—"}</td><td className="px-3 py-3 text-slate-300">{row.risk_level ?? "Unscored"}</td><td className="px-3 py-3 text-xs text-slate-400">TF-IDF {row.tfidf_status ?? "—"}<br />DistilBERT {row.distilbert_status ?? "—"}</td><td className="px-3 py-3 text-xs text-slate-400">{row.validation_status}</td></tr>)}</tbody></table></div></section>}</main></div>
}
