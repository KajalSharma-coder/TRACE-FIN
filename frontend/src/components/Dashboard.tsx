import { DashboardResponse } from "../lib/api"
import { Navbar } from "./Navbar"

type DashboardProps = {
  data: DashboardResponse
  userName: string
  onLogout: () => void
  onDashboard: () => void
  onAnalyze: () => void
  onUrlAnalyze: () => void
  onImageAnalyze: () => void
  onPdfAnalyze: () => void
  onDocxAnalyze: () => void
  onCsvAnalyze: () => void
  onInvestigations: () => void
  onEvidence: () => void
  onReports: () => void
  loggingOut: boolean
}

const riskOrder = ["Critical", "High", "Medium", "Low"]

function riskTone(level: string): string {
  if (level === "Critical") return "border-rose-400/30 bg-rose-400/10 text-rose-200"
  if (level === "High") return "border-orange-400/30 bg-orange-400/10 text-orange-200"
  if (level === "Medium") return "border-amber-400/30 bg-amber-400/10 text-amber-200"
  return "border-emerald-400/30 bg-emerald-400/10 text-emerald-200"
}

export function Dashboard({ data, userName, onLogout, onDashboard, onAnalyze, onUrlAnalyze, onImageAnalyze, onPdfAnalyze, onDocxAnalyze, onCsvAnalyze, onInvestigations, onEvidence, onReports, loggingOut }: DashboardProps) {
  const maxRisk = Math.max(...riskOrder.map((level) => data.risk_counts[level] ?? 0), 1)
  const topCategories = Object.entries(data.category_counts).sort((a, b) => b[1] - a[1]).slice(0, 6)
  const maxActivity = Math.max(...data.activity.map((item) => item.count), 1)
  const highRisk = (data.risk_counts.High ?? 0) + (data.risk_counts.Critical ?? 0)

  return (
    <div className="min-h-screen bg-trace-ink text-slate-100">
      <Navbar userName={userName} loggingOut={loggingOut} onDashboard={onDashboard} onAnalyze={onAnalyze} onUrlAnalyze={onUrlAnalyze} onImageAnalyze={onImageAnalyze} onPdfAnalyze={onPdfAnalyze} onDocxAnalyze={onDocxAnalyze} onCsvAnalyze={onCsvAnalyze} onInvestigations={onInvestigations} onEvidence={onEvidence} onReports={onReports} onLogout={onLogout} />

      <main className="mx-auto max-w-[1500px] px-5 py-8 sm:px-8 lg:py-10">
        <div className="mb-8 flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-trace-gold">Operational overview</p>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-50">Risk intelligence at a glance</h1>
            <p className="mt-2 text-sm text-trace-muted">Persisted investigator analyses, excluding synthetic demonstration records.</p>
          </div>
          {data.demo_count > 0 && <span className="rounded-full border border-trace-line px-3 py-1.5 text-xs text-trace-muted">{data.demo_count} demo record{data.demo_count === 1 ? "" : "s"} excluded</span>}
        </div>

        <section aria-label="Dashboard metrics" className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
          {[
            ["Total analyses", data.total, "text-trace-cyan"],
            ["High risk", highRisk, "text-rose-300"],
            ["Medium risk", data.risk_counts.Medium ?? 0, "text-amber-300"],
            ["Low risk", data.risk_counts.Low ?? 0, "text-emerald-300"],
            ["Open cases", data.status_counts.Open ?? 0, "text-sky-300"],
          ].map(([label, value, tone]) => (
            <div className="rounded-xl border border-trace-line bg-trace-navy/75 p-5" key={String(label)}>
              <p className="text-xs uppercase tracking-[0.14em] text-trace-muted">{label}</p>
              <p className={`mt-3 text-3xl font-semibold ${tone}`}>{value}</p>
            </div>
          ))}
        </section>

        {data.total === 0 ? (
          <div className="mt-6 rounded-xl border border-trace-line bg-trace-navy/50 px-5 py-8 text-sm text-trace-muted">
            No investigator-submitted analyses are available yet. Analyze an advertisement in the existing workspace to start building this dashboard.
          </div>
        ) : (
          <div className="mt-6 grid gap-6 xl:grid-cols-2">
            <section className="rounded-xl border border-trace-line bg-trace-navy/65 p-5" aria-labelledby="risk-title">
              <h2 id="risk-title" className="text-sm font-semibold text-slate-200">Risk distribution</h2>
              <div className="mt-6 space-y-4">
                {riskOrder.map((level) => {
                  const count = data.risk_counts[level] ?? 0
                  return <div className="flex items-center gap-3" key={level}>
                    <span className="w-16 text-xs text-trace-muted">{level}</span>
                    <div className="h-2 flex-1 rounded-full bg-trace-ink"><div className={`h-2 rounded-full ${level === "Critical" ? "bg-rose-400" : level === "High" ? "bg-orange-400" : level === "Medium" ? "bg-amber-400" : "bg-emerald-400"}`} style={{ width: `${(count / maxRisk) * 100}%` }} /></div>
                    <span className="w-8 text-right text-xs text-slate-300">{count}</span>
                  </div>
                })}
              </div>
            </section>

            <section className="rounded-xl border border-trace-line bg-trace-navy/65 p-5" aria-labelledby="activity-title">
              <h2 id="activity-title" className="text-sm font-semibold text-slate-200">Recent analysis activity</h2>
              {data.activity.length === 0 ? <p className="mt-6 text-sm text-trace-muted">Activity will appear after analyses are saved.</p> : <div className="mt-6 flex h-28 items-end gap-2 overflow-x-auto">{data.activity.slice(-14).map((item) => <div className="flex min-w-8 flex-1 flex-col items-center gap-2" key={item.date}><div className="w-full rounded-t bg-trace-cyan/70" style={{ height: `${Math.max((item.count / maxActivity) * 88, 6)}px` }} title={`${item.date}: ${item.count}`} /><span className="text-[9px] text-slate-500">{item.date.slice(5)}</span></div>)}</div>}
            </section>
          </div>
        )}

        <section className="mt-6 rounded-xl border border-trace-line bg-trace-navy/65 p-5" aria-labelledby="recent-title">
          <div className="flex items-center justify-between gap-3"><h2 id="recent-title" className="text-sm font-semibold text-slate-200">Recent analyses</h2><span className="text-xs text-trace-muted">{data.recent.length} shown</span></div>
          {data.recent.length === 0 ? <p className="mt-6 text-sm text-trace-muted">No recent investigator-submitted records to show.</p> : <div className="mt-4 overflow-x-auto"><table className="w-full min-w-[680px] text-left text-sm"><thead className="border-b border-trace-line text-xs uppercase tracking-[0.12em] text-slate-500"><tr><th className="px-3 py-3 font-medium">Record</th><th className="px-3 py-3 font-medium">Advertisement</th><th className="px-3 py-3 font-medium">Risk</th><th className="px-3 py-3 font-medium">Status</th><th className="px-3 py-3 font-medium">Submitted</th></tr></thead><tbody>{data.recent.map((record) => <tr className="border-b border-trace-line/60 last:border-0" key={record.record_id}><td className="px-3 py-3 font-mono text-xs text-trace-cyan">{record.record_id}</td><td className="max-w-[300px] truncate px-3 py-3 text-slate-300">{record.advertisement || "—"}</td><td className="px-3 py-3"><span className={`inline-flex rounded-full border px-2.5 py-1 text-xs ${riskTone(record.risk_level)}`}>{record.risk_level}{record.risk_score !== null ? ` · ${record.risk_score}` : ""}</span></td><td className="px-3 py-3 text-slate-400">{record.status}</td><td className="px-3 py-3 text-xs text-slate-500">{record.submitted_at.replace("T", " ").slice(0, 16)}</td></tr>)}</tbody></table></div>}
        </section>

        {topCategories.length > 0 && <section className="mt-6 rounded-xl border border-trace-line bg-trace-navy/65 p-5" aria-labelledby="categories-title"><h2 id="categories-title" className="text-sm font-semibold text-slate-200">Frequently observed threat categories</h2><div className="mt-5 flex flex-wrap gap-2">{topCategories.map(([category, count]) => <span className="rounded-full border border-trace-cyan/25 bg-trace-cyan/10 px-3 py-1.5 text-xs text-trace-cyan" key={category}>{category} · {count}</span>)}</div></section>}
      </main>
    </div>
  )
}
