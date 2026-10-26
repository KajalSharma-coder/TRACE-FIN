import { KeyboardEvent, useEffect, useRef, useState } from "react"

type NavAction = {
  id: string
  label: string
  onSelect: () => void
}

type NavGroup = {
  id: "analyze" | "investigations"
  label: string
  items: NavAction[]
}

type NavbarProps = {
  userName: string
  loggingOut: boolean
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
  onLogout: () => void
}

const chevron = <span aria-hidden="true" className="text-[10px] text-slate-500">⌄</span>

function focusMenuItem(event: KeyboardEvent<HTMLButtonElement>, direction: 1 | -1, menu: HTMLElement) {
  if (!(["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key))) return
  event.preventDefault()
  const items = Array.from(menu.querySelectorAll<HTMLButtonElement>("[role=menuitem]"))
  if (!items.length) return
  const current = items.indexOf(event.currentTarget)
  const next = event.key === "Home" ? 0 : event.key === "End" ? items.length - 1 : (current + direction + items.length) % items.length
  items[next]?.focus()
}

function MenuItems({ items, menuId, onSelect }: { items: NavAction[]; menuId: string; onSelect: () => void }) {
  return (
    <div className="space-y-0.5 p-1.5" id={menuId} role="menu">
      {items.map((item) => (
        <button
          className="flex w-full items-center rounded-md px-3 py-2.5 text-left text-sm text-slate-300 transition hover:bg-trace-cyan/10 hover:text-trace-cyan focus:bg-trace-cyan/10 focus:text-trace-cyan focus:outline-none"
          key={item.id}
          onClick={() => { item.onSelect(); onSelect() }}
          onKeyDown={(event) => {
            const menu = event.currentTarget.parentElement
            if (menu) focusMenuItem(event, event.key === "ArrowUp" ? -1 : 1, menu)
          }}
          role="menuitem"
          type="button"
        >
          {item.label}
        </button>
      ))}
    </div>
  )
}

function GroupButton({ group, open, onToggle, menuId }: { group: NavGroup; open: boolean; onToggle: () => void; menuId: string }) {
  return (
    <button
      aria-controls={menuId}
      aria-expanded={open}
      className={`inline-flex items-center gap-2 rounded-md px-3 py-2 text-sm transition focus:outline-none focus-visible:ring-2 focus-visible:ring-trace-cyan ${open ? "bg-trace-cyan/10 text-trace-cyan" : "text-slate-300 hover:bg-white/[0.04] hover:text-trace-cyan"}`}
      onClick={onToggle}
      onKeyDown={(event) => { if (event.key === "ArrowDown") { event.preventDefault(); onToggle() } }}
      type="button"
    >
      {group.label} {chevron}
    </button>
  )
}

export function Navbar({ userName, loggingOut, onDashboard, onAnalyze, onUrlAnalyze, onImageAnalyze, onPdfAnalyze, onDocxAnalyze, onCsvAnalyze, onInvestigations, onEvidence, onReports, onLogout }: NavbarProps) {
  const [openMenu, setOpenMenu] = useState<string | null>(null)
  const [mobileOpen, setMobileOpen] = useState(false)
  const navRef = useRef<HTMLElement>(null)

  const groups: NavGroup[] = [
    {
      id: "analyze",
      label: "Analyze",
      items: [
        { id: "advertisement", label: "Analyze advertisement", onSelect: onAnalyze },
        { id: "url", label: "Inspect URL", onSelect: onUrlAnalyze },
        { id: "image", label: "Analyze image / OCR", onSelect: onImageAnalyze },
        { id: "pdf", label: "Analyze PDF", onSelect: onPdfAnalyze },
        { id: "docx", label: "Analyze DOCX", onSelect: onDocxAnalyze },
        { id: "csv", label: "Analyze CSV", onSelect: onCsvAnalyze },
      ],
    },
    {
      id: "investigations",
      label: "Investigations",
      items: [
        { id: "cases", label: "Cases", onSelect: onInvestigations },
        { id: "evidence", label: "Evidence Vault", onSelect: onEvidence },
      ],
    },
  ]

  const closeMenus = () => { setOpenMenu(null); setMobileOpen(false) }

  useEffect(() => {
    function handleDocumentClick(event: MouseEvent) {
      if (!navRef.current?.contains(event.target as Node)) closeMenus()
    }
    function handleEscape(event: globalThis.KeyboardEvent) {
      if (event.key === "Escape") { closeMenus(); navRef.current?.querySelector<HTMLButtonElement>("[aria-expanded=true]")?.focus() }
    }
    document.addEventListener("mousedown", handleDocumentClick)
    document.addEventListener("keydown", handleEscape)
    return () => { document.removeEventListener("mousedown", handleDocumentClick); document.removeEventListener("keydown", handleEscape) }
  }, [])

  return (
    <nav aria-label="Primary navigation" className="relative z-20 border-b border-trace-line/70 bg-trace-navy/90 px-4 py-3 sm:px-6 lg:px-8" ref={navRef}>
      <div className="mx-auto flex max-w-[1500px] items-center justify-between gap-3">
        <button className="flex min-w-0 items-center gap-3 rounded-lg text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-trace-cyan" onClick={() => { onDashboard(); closeMenus() }} type="button">
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-trace-cyan/50 bg-trace-cyan/10 text-xs font-bold text-trace-cyan">TF</span>
          <span className="min-w-0">
            <span className="block truncate text-sm font-semibold tracking-[0.2em] text-trace-cyan">TRACE//FIN</span>
            <span className="mt-0.5 block truncate text-[9px] uppercase tracking-[0.16em] text-trace-muted">Investigator dashboard</span>
          </span>
        </button>

        <div className="hidden items-center gap-1 lg:flex">
          <button aria-current="page" className="rounded-md bg-trace-cyan/10 px-3 py-2 text-sm text-trace-cyan focus:outline-none focus-visible:ring-2 focus-visible:ring-trace-cyan" onClick={() => { onDashboard(); closeMenus() }} type="button">Dashboard</button>
          {groups.map((group) => {
            const menuId = `desktop-${group.id}-menu`
            return <div className="relative" key={group.id}>
              <GroupButton group={group} menuId={menuId} onToggle={() => setOpenMenu(openMenu === group.id ? null : group.id)} open={openMenu === group.id} />
              {openMenu === group.id && <div className="absolute left-0 top-full mt-2 min-w-56 overflow-hidden rounded-lg border border-trace-line bg-trace-navy shadow-2xl shadow-black/30"><MenuItems items={group.items} menuId={menuId} onSelect={closeMenus} /></div>}
            </div>
          })}
          <button className="rounded-md px-3 py-2 text-sm text-slate-300 transition hover:bg-white/[0.04] hover:text-trace-cyan focus:outline-none focus-visible:ring-2 focus-visible:ring-trace-cyan" onClick={() => { onReports(); closeMenus() }} type="button">Reports</button>
        </div>

        <div className="hidden items-center gap-2 lg:flex">
          <span className="max-w-36 truncate px-2 text-sm text-slate-400" title={userName}>{userName}</span>
          <div className="relative">
            <button aria-controls="desktop-account-menu" aria-expanded={openMenu === "account"} className={`rounded-md border px-3 py-2 text-xs transition focus:outline-none focus-visible:ring-2 focus-visible:ring-trace-cyan ${openMenu === "account" ? "border-trace-cyan/50 bg-trace-cyan/10 text-trace-cyan" : "border-trace-line text-slate-300 hover:border-trace-cyan hover:text-trace-cyan"}`} onClick={() => setOpenMenu(openMenu === "account" ? null : "account")} type="button">Account {chevron}</button>
            {openMenu === "account" && <div className="absolute right-0 top-full mt-2 min-w-44 overflow-hidden rounded-lg border border-trace-line bg-trace-navy shadow-2xl shadow-black/30" id="desktop-account-menu" role="menu"><button className="w-full px-3 py-2.5 text-left text-sm text-slate-300 hover:bg-rose-400/10 hover:text-rose-200 focus:bg-rose-400/10 focus:outline-none" disabled={loggingOut} onClick={() => { onLogout(); closeMenus() }} role="menuitem" type="button">{loggingOut ? "Signing out…" : "Sign out"}</button></div>}
          </div>
        </div>

        <button aria-controls="mobile-navigation" aria-expanded={mobileOpen} aria-label={mobileOpen ? "Close navigation menu" : "Open navigation menu"} className="rounded-lg border border-trace-line p-2.5 text-slate-300 transition hover:border-trace-cyan hover:text-trace-cyan focus:outline-none focus-visible:ring-2 focus-visible:ring-trace-cyan lg:hidden" onClick={() => setMobileOpen(!mobileOpen)} type="button">
          <span aria-hidden="true" className="block text-lg leading-none">{mobileOpen ? "×" : "☰"}</span>
        </button>
      </div>

      {mobileOpen && <div className="mt-3 border-t border-trace-line/70 pt-3 lg:hidden" id="mobile-navigation">
        <div className="space-y-1">
          <button className="w-full rounded-md bg-trace-cyan/10 px-3 py-2.5 text-left text-sm text-trace-cyan focus:outline-none focus-visible:ring-2 focus-visible:ring-trace-cyan" onClick={() => { onDashboard(); closeMenus() }} type="button">Dashboard</button>
          {groups.map((group) => {
            const menuId = `mobile-${group.id}-menu`
            return <div key={group.id}>
              <GroupButton group={group} menuId={menuId} onToggle={() => setOpenMenu(openMenu === `mobile-${group.id}` ? null : `mobile-${group.id}`)} open={openMenu === `mobile-${group.id}`} />
              {openMenu === `mobile-${group.id}` && <div className="mt-1 rounded-md border border-trace-line/70 bg-trace-ink/40"><MenuItems items={group.items} menuId={menuId} onSelect={closeMenus} /></div>}
            </div>
          })}
          <button className="w-full rounded-md px-3 py-2.5 text-left text-sm text-slate-300 hover:bg-white/[0.04] hover:text-trace-cyan focus:outline-none focus-visible:ring-2 focus-visible:ring-trace-cyan" onClick={() => { onReports(); closeMenus() }} type="button">Reports</button>
          <div className="mt-2 flex items-center justify-between border-t border-trace-line/70 px-3 pt-3"><span className="truncate text-sm text-slate-400">{userName}</span><button className="rounded-md border border-trace-line px-3 py-2 text-xs text-slate-300 hover:border-rose-400/50 hover:text-rose-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-trace-cyan" disabled={loggingOut} onClick={() => { onLogout(); closeMenus() }} type="button">{loggingOut ? "Signing out…" : "Sign out"}</button></div>
        </div>
      </div>}
    </nav>
  )
}
