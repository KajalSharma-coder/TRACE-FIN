import { ChangeEvent, FormEvent, useEffect, useState } from "react"
import { analyzeImageText, AnalysisResponse, ApiError, extractImageText, ImageOcrResponse } from "../lib/api"

type ImageAnalysisPageProps = {
  onBack: () => void
  onUnauthorized: () => void
}

function verdictTone(verdict: string): string {
  const value = verdict.toUpperCase()
  if (value.includes("HIGH") || value.includes("CRITICAL")) return "border-rose-400/40 bg-rose-400/10 text-rose-200"
  if (value.includes("MEDIUM")) return "border-amber-400/40 bg-amber-400/10 text-amber-200"
  return "border-emerald-400/40 bg-emerald-400/10 text-emerald-200"
}

export function ImageAnalysisPage({ onBack, onUnauthorized }: ImageAnalysisPageProps) {
  const [file, setFile] = useState<File | null>(null)
  const [previewUrl, setPreviewUrl] = useState<string | null>(null)
  const [ocr, setOcr] = useState<ImageOcrResponse | null>(null)
  const [text, setText] = useState("")
  const [result, setResult] = useState<AnalysisResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!file) {
      setPreviewUrl(null)
      return
    }
    const url = URL.createObjectURL(file)
    setPreviewUrl(url)
    return () => URL.revokeObjectURL(url)
  }, [file])

  async function chooseFile(event: ChangeEvent<HTMLInputElement>) {
    const selected = event.target.files?.[0] ?? null
    setFile(selected)
    setOcr(null)
    setText("")
    setResult(null)
    setError(null)
    if (!selected) return
    setLoading(true)
    try {
      const response = await extractImageText(selected)
      setOcr(response)
      if (!response.valid) setError(response.error ?? "Image validation failed.")
      else if (response.ocr.available && response.ocr.text) setText(response.ocr.text)
      else setError(response.ocr.error ?? "No readable text was detected in the image.")
    } catch (caught: unknown) {
      if (caught instanceof ApiError && caught.status === 401) {
        onUnauthorized()
        return
      }
      setError(caught instanceof Error ? caught.message : "Image OCR service unavailable.")
    } finally {
      setLoading(false)
    }
  }

  async function submitText(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const trimmed = text.trim()
    setError(null)
    setResult(null)
    if (!trimmed) {
      setError("Enter or correct OCR text before running analysis.")
      return
    }
    setAnalyzing(true)
    try {
      setResult(await analyzeImageText(trimmed))
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

  return (
    <div className="min-h-screen bg-trace-ink text-slate-100">
      <header className="border-b border-trace-line/70 bg-trace-navy/80 px-5 py-5 sm:px-8"><div className="mx-auto flex max-w-[1200px] items-center justify-between gap-4"><div><p className="text-sm font-semibold tracking-[0.2em] text-trace-cyan">TRACE//FIN</p><p className="mt-1 text-xs uppercase tracking-[0.16em] text-trace-muted">Image OCR analysis</p></div><button className="rounded-lg border border-trace-line px-3 py-2 text-xs text-slate-300 hover:border-trace-cyan hover:text-trace-cyan" onClick={onBack} type="button">Back to dashboard</button></div></header>
      <main className="mx-auto max-w-[1200px] px-5 py-8 sm:px-8 lg:py-10">
        <div className="mb-8"><p className="text-xs font-semibold uppercase tracking-[0.2em] text-trace-gold">Image intake</p><h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-50">Extract and analyze advertisement text</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-trace-muted">Images are validated and processed in backend memory using the existing local EasyOCR/Tesseract fallback. Uploads are not persisted or sent to external OCR services.</p></div>
        <section className="rounded-xl border border-trace-line bg-trace-navy/70 p-5 sm:p-6"><label className="block text-sm font-medium text-slate-200" htmlFor="image-upload">Advertisement image</label><p className="mt-2 text-xs text-trace-muted">JPEG, PNG, or WEBP · maximum 10 MB · dimensions 50–8000 px</p><input accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp" className="mt-4 block w-full rounded-lg border border-dashed border-trace-line bg-trace-ink/50 px-4 py-4 text-sm text-slate-300 file:mr-4 file:rounded-md file:border-0 file:bg-trace-cyan file:px-3 file:py-2 file:text-xs file:font-semibold file:text-trace-ink" id="image-upload" onChange={chooseFile} type="file" />{loading && <p className="mt-4 text-sm text-trace-cyan" role="status">Validating image and running local OCR…</p>}{previewUrl && <div className="mt-5 grid gap-5 lg:grid-cols-[280px_1fr]"><img alt="Local preview of selected advertisement" className="max-h-64 w-full rounded-lg border border-trace-line bg-trace-ink object-contain" src={previewUrl} />{ocr && <div className="rounded-lg border border-trace-line/70 bg-trace-ink/40 p-4 text-sm text-slate-300"><p className="text-xs uppercase tracking-[0.14em] text-trace-muted">Image validation</p><p className="mt-2">{ocr.dimensions.join(" × ")} px · {ocr.file_size_kb.toFixed(1)} KB</p><p className="mt-2 text-trace-muted">{ocr.ocr.available ? `${ocr.ocr.engine ?? "OCR"} available${ocr.ocr.confidence !== null ? ` · ${ocr.ocr.confidence.toFixed(1)}% confidence` : ""}` : "OCR unavailable"}</p></div>}</div>}</section>
        <form className="mt-6 rounded-xl border border-trace-line bg-trace-navy/70 p-5 sm:p-6" onSubmit={submitText}><label className="block text-sm font-medium text-slate-200" htmlFor="ocr-text">Review and edit extracted text</label><p className="mt-2 text-xs text-trace-muted">Correct OCR errors or add missing context before authorizing financial-advertisement analysis.</p><textarea className="mt-4 min-h-48 w-full resize-y rounded-lg border border-trace-line bg-trace-ink/80 px-4 py-3 text-sm leading-6 text-slate-100 outline-none focus:border-trace-cyan focus:ring-2 focus:ring-trace-cyan/20" id="ocr-text" maxLength={200000} onChange={(event) => setText(event.target.value)} placeholder="OCR text will appear here after a valid image is processed…" value={text} /><div className="mt-3 flex justify-between gap-3 text-xs text-trace-muted"><span>{text.length.toLocaleString()} / 200,000 characters</span><button className="rounded-lg bg-trace-cyan px-5 py-3 text-sm font-semibold text-trace-ink transition hover:bg-[#62e6dd] disabled:cursor-wait disabled:opacity-60" disabled={analyzing || loading} type="submit">{analyzing ? "Analyzing…" : "Analyze corrected text"}</button></div>{error && <p className="mt-4 rounded-lg border border-rose-400/30 bg-rose-400/10 px-3 py-2.5 text-sm text-rose-200" role="alert">{error}</p>}</form>
        {result && <section className="mt-6 space-y-5" aria-live="polite"><div className={`rounded-xl border p-5 ${verdictTone(result.final_verdict)}`}><div className="flex items-center justify-between gap-3"><div><p className="text-xs uppercase tracking-[0.14em]">Final verdict</p><p className="mt-2 text-3xl font-semibold">{result.final_verdict}</p></div><div className="text-right"><p className="text-xs uppercase tracking-[0.14em]">Risk score</p><p className="mt-2 text-3xl font-semibold">{result.final_score ?? "Unavailable"}</p></div></div></div><div className="grid gap-5 lg:grid-cols-2"><section className="rounded-xl border border-trace-line bg-trace-navy/65 p-5"><h2 className="text-sm font-semibold">Assessment</h2><p className="mt-4 text-sm leading-7 text-slate-300">{result.explanation}</p><p className="mt-4 text-sm leading-7 text-slate-300"><span className="text-xs uppercase tracking-[0.12em] text-trace-muted">Recommendation · </span>{result.recommendation}</p></section><section className="rounded-xl border border-trace-line bg-trace-navy/65 p-5"><h2 className="text-sm font-semibold">Model availability</h2><div className="mt-4 space-y-3">{Object.entries(result.engine_status).map(([engine, status]) => <div className="flex justify-between border-b border-trace-line/60 pb-3 text-sm last:border-0" key={engine}><span className="text-slate-400">{engine}</span><span className={status === "available" ? "text-emerald-300" : "text-amber-300"}>{status}</span></div>)}</div></section></div>{(result.matched_categories.length > 0 || result.evidence.length > 0) && <section className="rounded-xl border border-trace-line bg-trace-navy/65 p-5"><h2 className="text-sm font-semibold">Detected indicators</h2>{result.matched_categories.length > 0 && <p className="mt-3 text-sm text-amber-200">{result.matched_categories.join(" · ")}</p>}{result.evidence.length > 0 && <ul className="mt-3 list-disc space-y-2 pl-5 text-sm leading-6 text-slate-300">{result.evidence.map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}</ul>}</section>}</section>}
      </main>
    </div>
  )
}
