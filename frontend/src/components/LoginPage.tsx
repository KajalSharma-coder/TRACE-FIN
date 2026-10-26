import { FormEvent, useState } from "react"
import { HealthState } from "../lib/api"

type LoginPageProps = {
  healthState: HealthState
  healthError: string | null
  email: string
  password: string
  authenticating: boolean
  loginError: string | null
  onSubmit: (event: FormEvent<HTMLFormElement>) => void
  onRegister: (name: string, email: string, password: string, confirmation: string) => Promise<void>
  onEmailChange: (value: string) => void
  onPasswordChange: (value: string) => void
}

function HealthStatus({ state }: { state: HealthState }) {
  const label = state === "online" ? "API online" : state === "offline" ? "API unavailable" : "Checking API"
  const dot = state === "online" ? "bg-trace-cyan" : state === "offline" ? "bg-amber-300" : "bg-slate-500"
  return <span className="inline-flex items-center gap-2 text-[11px] uppercase tracking-[0.18em] text-slate-400"><span className={`h-1.5 w-1.5 rounded-full ${dot}`} />{label}</span>
}

export function LoginPage({ healthState, healthError, email, password, authenticating, loginError, onSubmit, onRegister, onEmailChange, onPasswordChange }: LoginPageProps) {
  const [mode, setMode] = useState<"login" | "register">("login")
  const [name, setName] = useState("")
  const [registrationEmail, setRegistrationEmail] = useState("")
  const [registrationPassword, setRegistrationPassword] = useState("")
  const [confirmation, setConfirmation] = useState("")
  const [registering, setRegistering] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmation, setShowConfirmation] = useState(false)
  const [registrationError, setRegistrationError] = useState<string | null>(null)

  function switchMode(nextMode: "login" | "register") {
    setMode(nextMode)
    setRegistrationError(null)
    setShowPassword(false)
    setShowConfirmation(false)
  }

  async function submitRegistration(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const trimmedName = name.trim()
    const trimmedEmail = registrationEmail.trim()
    if (!trimmedName) return setRegistrationError("Enter your full name.")
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) return setRegistrationError("Enter a valid email address.")
    if (registrationPassword.length < 12) return setRegistrationError("Use a password with at least 12 characters.")
    if (registrationPassword !== confirmation) return setRegistrationError("Passwords do not match.")
    setRegistrationError(null)
    setRegistering(true)
    try {
      await onRegister(trimmedName, trimmedEmail, registrationPassword, confirmation)
    } catch (error: unknown) {
      setRegistrationError(error instanceof Error ? error.message : "Account creation failed. Please try again.")
    } finally {
      setRegistering(false)
    }
  }

  return <div className="min-h-screen overflow-x-hidden bg-trace-ink text-slate-100">
    <header className="mx-auto flex w-full max-w-7xl items-center justify-between px-5 py-6 sm:px-8 lg:px-10">
      <div>
        <p className="font-mono text-lg font-semibold tracking-[0.22em] text-trace-cyan">TRACE//FIN</p>
        <p className="mt-1 text-[10px] uppercase tracking-[0.28em] text-slate-500">Financial threat intelligence</p>
      </div>
      <HealthStatus state={healthState} />
    </header>

    <main className="mx-auto grid w-full max-w-7xl items-center gap-10 px-5 pb-12 pt-8 sm:px-8 lg:min-h-[calc(100vh-96px)] lg:grid-cols-[minmax(0,1fr)_minmax(440px,500px)] lg:gap-16 lg:px-10 lg:pb-20 lg:pt-10">
      <section className="max-w-xl">
        <p className="mb-5 font-mono text-xs uppercase tracking-[0.24em] text-trace-cyan">Signal intelligence workspace</p>
        <h1 className="max-w-lg text-4xl font-semibold leading-[1.05] tracking-tight text-white sm:text-5xl lg:text-[4.25rem]">Detect signals.<br /><span className="text-slate-400">Prioritize action.</span></h1>
        <p className="mt-6 max-w-md text-base leading-7 text-slate-400">Turn fragmented financial threat signals into clear, defensible investigations.</p>
        <div className="mt-8 grid gap-3 text-sm text-slate-300 sm:grid-cols-3 lg:max-w-xl lg:grid-cols-1">
          {[["01", "Analyze", "Surface suspicious patterns quickly."], ["02", "Investigate", "Connect evidence across a case."], ["03", "Act", "Preserve context for the next decision."]].map(([number, title, description]) => <div className="flex gap-3 border-l border-trace-line pl-4" key={number}><span className="font-mono text-xs text-trace-cyan">{number}</span><div><p className="font-medium text-slate-200">{title}</p><p className="mt-1 text-xs leading-5 text-slate-500">{description}</p></div></div>)}
        </div>
      </section>

      <section className="w-full max-w-[500px] justify-self-end rounded-2xl border border-trace-line bg-[#0d1b2e]/90 p-6 shadow-2xl shadow-black/20 sm:p-8" aria-live="polite">
        {mode === "login" ? <>
          <div className="mb-7"><p className="font-mono text-[11px] uppercase tracking-[0.2em] text-trace-cyan">Secure access</p><h2 className="mt-3 text-2xl font-semibold text-white">Sign in to TRACE//FIN</h2><p className="mt-2 text-sm text-slate-400">Continue to your investigator workspace.</p></div>
          {loginError && <p className="mb-4 rounded-lg border border-rose-400/30 bg-rose-400/5 px-3 py-2 text-sm text-rose-200" role="alert">{loginError}</p>}
          {healthError && <p className="mb-4 rounded-lg border border-amber-300/30 bg-amber-300/5 px-3 py-2 text-sm text-amber-100" role="status">{healthError}</p>}
          <form className="space-y-5" onSubmit={onSubmit}>
            <label className="block text-sm text-slate-300">Email address<input className="mt-2 w-full appearance-none rounded-lg border border-trace-line bg-trace-ink px-3 py-3 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-trace-cyan focus:ring-2 focus:ring-trace-cyan/20" type="email" autoComplete="email" placeholder="Enter your email address" value={email} onChange={(event) => onEmailChange(event.target.value)} required /></label>
            <label className="block text-sm text-slate-300">Password<input className="mt-2 w-full appearance-none rounded-lg border border-trace-line bg-trace-ink px-3 py-3 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-trace-cyan focus:ring-2 focus:ring-trace-cyan/20" type="password" autoComplete="current-password" placeholder="Enter your password" value={password} onChange={(event) => onPasswordChange(event.target.value)} required /></label>
            <button className="w-full rounded-lg bg-trace-cyan px-4 py-3 text-sm font-semibold text-trace-ink transition hover:bg-cyan-200 focus:outline-none focus:ring-2 focus:ring-trace-cyan focus:ring-offset-2 focus:ring-offset-[#0d1b2e] disabled:cursor-not-allowed disabled:opacity-60" disabled={authenticating} type="submit">{authenticating ? "Signing in…" : "Continue"}</button>
          </form>
          <p className="mt-6 border-t border-trace-line pt-5 text-center text-sm text-slate-500">New to TRACE-FIN? <button className="font-medium text-trace-cyan transition hover:text-cyan-200 focus:outline-none focus:ring-2 focus:ring-trace-cyan" type="button" onClick={() => switchMode("register")}>Create an account</button></p>
        </> : <>
          <div className="mb-7"><p className="font-mono text-[11px] uppercase tracking-[0.2em] text-trace-cyan">New investigator</p><h2 className="mt-3 text-2xl font-semibold text-white">Create your account</h2><p className="mt-2 text-sm text-slate-400">Set up secure access to the investigator workspace.</p></div>
          {registrationError && <p className="mb-4 rounded-lg border border-rose-400/30 bg-rose-400/5 px-3 py-2 text-sm text-rose-200" role="alert">{registrationError}</p>}
          {healthError && <p className="mb-4 rounded-lg border border-amber-300/30 bg-amber-300/5 px-3 py-2 text-sm text-amber-100" role="status">{healthError}</p>}
          <form className="space-y-4" onSubmit={submitRegistration}>
            <label className="block text-sm text-slate-300">Full name<input className="mt-2 w-full appearance-none rounded-lg border border-trace-line bg-trace-ink px-3 py-3 text-sm text-white outline-none transition focus:border-trace-cyan focus:ring-2 focus:ring-trace-cyan/20" type="text" autoComplete="name" value={name} onChange={(event) => setName(event.target.value)} required /></label>
            <label className="block text-sm text-slate-300">Email address<input className="mt-2 w-full appearance-none rounded-lg border border-trace-line bg-trace-ink px-3 py-3 text-sm text-white outline-none transition focus:border-trace-cyan focus:ring-2 focus:ring-trace-cyan/20" type="email" autoComplete="email" value={registrationEmail} onChange={(event) => setRegistrationEmail(event.target.value)} required /></label>
            <label className="block text-sm text-slate-300">Password<div className="relative mt-2"><input className="w-full appearance-none rounded-lg border border-trace-line bg-trace-ink px-3 py-3 pr-16 text-sm text-white outline-none transition focus:border-trace-cyan focus:ring-2 focus:ring-trace-cyan/20" type={showPassword ? "text" : "password"} autoComplete="new-password" value={registrationPassword} onChange={(event) => setRegistrationPassword(event.target.value)} required /><button className="absolute right-2 top-1/2 -translate-y-1/2 rounded px-2 py-1 text-xs text-slate-400 hover:text-trace-cyan focus:outline-none focus:ring-2 focus:ring-trace-cyan" type="button" aria-label={showPassword ? "Hide password" : "Show password"} aria-pressed={showPassword} onClick={() => setShowPassword((shown) => !shown)}>{showPassword ? "Hide" : "Show"}</button></div><span className="mt-1 block text-xs text-slate-500">At least 12 characters.</span></label>
            <label className="block text-sm text-slate-300">Confirm password<div className="relative mt-2"><input className="w-full appearance-none rounded-lg border border-trace-line bg-trace-ink px-3 py-3 pr-16 text-sm text-white outline-none transition focus:border-trace-cyan focus:ring-2 focus:ring-trace-cyan/20" type={showConfirmation ? "text" : "password"} autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} required /><button className="absolute right-2 top-1/2 -translate-y-1/2 rounded px-2 py-1 text-xs text-slate-400 hover:text-trace-cyan focus:outline-none focus:ring-2 focus:ring-trace-cyan" type="button" aria-label={showConfirmation ? "Hide confirmation password" : "Show confirmation password"} aria-pressed={showConfirmation} onClick={() => setShowConfirmation((shown) => !shown)}>{showConfirmation ? "Hide" : "Show"}</button></div></label>
            <button className="w-full rounded-lg bg-trace-cyan px-4 py-3 text-sm font-semibold text-trace-ink transition hover:bg-cyan-200 focus:outline-none focus:ring-2 focus:ring-trace-cyan focus:ring-offset-2 focus:ring-offset-[#0d1b2e] disabled:cursor-not-allowed disabled:opacity-60" disabled={registering} type="submit">{registering ? "Creating account…" : "Create account"}</button>
          </form>
          <p className="mt-6 border-t border-trace-line pt-5 text-center text-sm text-slate-500">Already have an account? <button className="font-medium text-trace-cyan transition hover:text-cyan-200 focus:outline-none focus:ring-2 focus:ring-trace-cyan" type="button" onClick={() => switchMode("login")}>Sign in</button></p>
        </>}
      </section>
    </main>
  </div>
}
