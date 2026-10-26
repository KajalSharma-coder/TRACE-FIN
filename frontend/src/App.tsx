import { FormEvent, useEffect, useState } from "react"
import { AuthUser, DashboardResponse, getCurrentSession, getDashboard, getHealth, HealthState, login as loginWithApi, logout as logoutFromApi, register as registerWithApi } from "./lib/api"
import { Dashboard } from "./components/Dashboard"
import { AnalysisPage } from "./components/AnalysisPage"
import { UrlAnalysisPage } from "./components/UrlAnalysisPage"
import { ImageAnalysisPage } from "./components/ImageAnalysisPage"
import { DocumentAnalysisPage } from "./components/DocumentAnalysisPage"
import { CsvAnalysisPage } from "./components/CsvAnalysisPage"
import { InvestigationsPage } from "./components/InvestigationsPage"
import { EvidenceVaultPage } from "./components/EvidenceVaultPage"
import { ReportsPage } from "./components/ReportsPage"
import { LoginPage } from "./components/LoginPage"

type View = "dashboard" | "analysis" | "url" | "image" | "pdf" | "docx" | "csv" | "investigations" | "evidence" | "reports"

function App() {
  const [healthState, setHealthState] = useState<HealthState>("checking")
  const [healthError, setHealthError] = useState<string | null>(null)
  const [loginError, setLoginError] = useState<string | null>(null)
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [authenticating, setAuthenticating] = useState(false)
  const [authenticatedUser, setAuthenticatedUser] = useState<AuthUser | null>(null)
  const [dashboard, setDashboard] = useState<DashboardResponse | null>(null)
  const [dashboardLoading, setDashboardLoading] = useState(false)
  const [dashboardError, setDashboardError] = useState<string | null>(null)
  const [loggingOut, setLoggingOut] = useState(false)
  const [view, setView] = useState<View>("dashboard")

  useEffect(() => {
    const controller = new AbortController()
    getHealth(controller.signal)
      .then(() => { setHealthState("online"); setHealthError(null) })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return
        setHealthState("offline")
        setHealthError("The API could not be reached. Start the backend and try again.")
      })
    return () => controller.abort()
  }, [])

  async function loadDashboard() {
    setDashboardLoading(true)
    setDashboardError(null)
    try { setDashboard(await getDashboard()) }
    catch (error: unknown) { setDashboardError(error instanceof Error ? error.message : "Unable to load dashboard data.") }
    finally { setDashboardLoading(false) }
  }

  useEffect(() => {
    getCurrentSession()
      .then((user) => { if (user) { setAuthenticatedUser(user); return loadDashboard() } })
      .catch(() => setLoginError("Unable to verify the current session."))
  }, [])

  async function handleLoginSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setLoginError(null)
    setAuthenticating(true)
    try {
      const user = await loginWithApi(email, password)
      setAuthenticatedUser(user)
      setPassword("")
      setView("dashboard")
      await loadDashboard()
    } catch (error: unknown) {
      setLoginError(error instanceof Error ? error.message : "Sign-in failed. Please try again.")
    } finally { setAuthenticating(false) }
  }

  async function handleLogout() {
    setLoggingOut(true)
    try {
      await logoutFromApi()
      setAuthenticatedUser(null)
      setDashboard(null)
      setView("dashboard")
      setEmail("")
      setPassword("")
      setLoginError(null)
    } catch (error: unknown) {
      setDashboardError(error instanceof Error ? error.message : "Unable to sign out securely.")
    } finally { setLoggingOut(false) }
  }

  async function handleRegister(name: string, registrationEmail: string, registrationPassword: string, confirmation: string) {
    setLoginError(null)
    const user = await registerWithApi(name, registrationEmail, registrationPassword, confirmation)
    setAuthenticatedUser(user)
    setPassword("")
    setView("dashboard")
    await loadDashboard()
  }

  const handleUnauthorized = () => {
    setAuthenticatedUser(null)
    setDashboard(null)
    setView("dashboard")
    setLoginError("Your session expired. Please sign in again.")
  }

  if (!authenticatedUser) {
    return <LoginPage healthState={healthState} healthError={healthError} email={email} password={password} authenticating={authenticating} loginError={loginError} onSubmit={handleLoginSubmit} onRegister={handleRegister} onEmailChange={(value) => { setEmail(value); setLoginError(null) }} onPasswordChange={(value) => { setPassword(value); setLoginError(null) }} />
  }

  if (view === "analysis") return <AnalysisPage onBack={() => setView("dashboard")} onUnauthorized={handleUnauthorized} />
  if (view === "url") return <UrlAnalysisPage onBack={() => setView("dashboard")} onUnauthorized={handleUnauthorized} />
  if (view === "image") return <ImageAnalysisPage onBack={() => setView("dashboard")} onUnauthorized={handleUnauthorized} />
  if (view === "pdf") return <DocumentAnalysisPage kind="pdf" onBack={() => setView("dashboard")} onUnauthorized={handleUnauthorized} />
  if (view === "docx") return <DocumentAnalysisPage kind="docx" onBack={() => setView("dashboard")} onUnauthorized={handleUnauthorized} />
  if (view === "csv") return <CsvAnalysisPage onBack={() => setView("dashboard")} onUnauthorized={handleUnauthorized} />
  if (view === "investigations") return <InvestigationsPage onBack={() => setView("dashboard")} onUrlAnalyze={() => setView("url")} onUnauthorized={handleUnauthorized} />
  if (view === "evidence") return <EvidenceVaultPage onBack={() => setView("dashboard")} onUnauthorized={handleUnauthorized} />
  if (view === "reports") return <ReportsPage onBack={() => setView("dashboard")} onUnauthorized={handleUnauthorized} />
  if (dashboardLoading) return <div className="grid min-h-screen place-items-center bg-trace-ink text-sm text-trace-muted">Loading dashboard data…</div>
  if (dashboardError || !dashboard) return <div className="grid min-h-screen place-items-center bg-trace-ink px-5 text-center text-sm text-rose-200"><div><p>{dashboardError ?? "Dashboard data is unavailable."}</p><button className="mt-4 rounded-lg border border-trace-line px-4 py-2 text-xs text-slate-300 hover:border-trace-cyan hover:text-trace-cyan" onClick={loadDashboard} type="button">Retry</button></div></div>

  return <Dashboard data={dashboard} userName={authenticatedUser.name} onDashboard={() => setView("dashboard")} onAnalyze={() => setView("analysis")} onUrlAnalyze={() => setView("url")} onImageAnalyze={() => setView("image")} onPdfAnalyze={() => setView("pdf")} onDocxAnalyze={() => setView("docx")} onCsvAnalyze={() => setView("csv")} onInvestigations={() => setView("investigations")} onEvidence={() => setView("evidence")} onReports={() => setView("reports")} onLogout={handleLogout} loggingOut={loggingOut} />
}

export default App
