"""Safe, display-only public landing page preview markup."""

from __future__ import annotations

from html import escape


def dashboard_preview_markup(snapshot: dict) -> str:
    """Build a dashboard preview from real metrics or clearly marked illustration."""
    has_real_records = bool(snapshot.get("total"))
    if has_real_records:
        total = int(snapshot["total"])
        risks = snapshot.get("risk_counts", {})
        high = int(risks.get("High", 0)) + int(risks.get("Critical", 0))
        medium = int(risks.get("Medium", 0))
        low = int(risks.get("Low", 0))
        high_pct, medium_pct, low_pct = (round(v * 100 / total) for v in (high, medium, low))
        score = round(sum(float(r.get("risk_score") or 0) for r in snapshot.get("recent", [])) /
                      max(1, min(total, len(snapshot.get("recent", [])))))
        activity = sum(int(item.get("count", 0)) for item in snapshot.get("activity", []))
        label = "LIVE WORKSPACE DATA · SYNTHETIC EXAMPLES EXCLUDED"
        recent = snapshot.get("recent", [])[:3]
        rows = "".join(
            "<div class='preview-row'><span class='preview-doc'>↗</span>"
            "<span class='preview-name'>Saved advertisement analysis</span>"
            f"<span class='preview-risk risk-{escape((row.get('risk_level') or 'low').lower())}'>{escape(row.get('risk_level') or 'Low')}</span>"
            f"<span class='preview-score'>{round(float(row.get('risk_score') or 0))}/100</span></div>"
            for row in recent
        )
        if not rows:
            rows = "<div class='preview-empty'>No saved analyses available.</div>"
    else:
        high_pct, medium_pct, low_pct = 42, 33, 25
        score, activity = 72, 12
        label = "ILLUSTRATIVE PREVIEW · EXAMPLE METRICS · NOT STORED AS CASES"
        rows = "".join((
            "<div class='preview-row'><span class='preview-doc'>↗</span><span class='preview-name'>Personal loan offer · urgent</span><span class='preview-risk risk-high'>High risk</span><span class='preview-score'>92/100</span></div>",
            "<div class='preview-row'><span class='preview-doc'>⌁</span><span class='preview-name'>Bank credit card promotion</span><span class='preview-risk risk-medium'>Medium</span><span class='preview-score'>56/100</span></div>",
            "<div class='preview-row'><span class='preview-doc'>▧</span><span class='preview-name'>Investment opportunity</span><span class='preview-risk risk-low'>Low risk</span><span class='preview-score'>18/100</span></div>",
        ))
    return f"""
    <div class="preview-shell">
      <div class="preview-topbar"><span class="preview-logo">TRACE//FIN</span><span class="preview-online"><i></i> SYSTEM ONLINE</span></div>
      <div class="preview-content">
        <aside class="preview-side"><div class="preview-nav active">◈ &nbsp; Overview</div><div class="preview-nav">⌕ &nbsp; Advertisement analysis</div><div class="preview-nav">▧ &nbsp; Image / OCR</div><div class="preview-nav">⌁ &nbsp; URL analysis</div><div class="preview-nav">▤ &nbsp; Case management</div></aside>
        <div class="preview-main">
          <div class="preview-heading"><div><small>THREAT MONITOR</small><h3>Investigation overview</h3></div><span class="preview-live-label">{label}</span></div>
          <div class="preview-metrics">
            <div class="preview-score-card"><span class="preview-muted">AVERAGE RISK SCORE</span><strong><b>{score}</b><small> / 100</small></strong><div class="score-track"><i style="width:{score}%"></i></div><span class="preview-muted">Based on available recent analyses</span></div>
            <div class="preview-activity"><span class="preview-muted">ANALYSIS ACTIVITY</span><strong>{activity}</strong><small>saved analyses</small><div class="sparkline"><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div></div>
            <div class="preview-distribution"><span class="preview-muted">RISK DISTRIBUTION</span>
              <div class="preview-bar-label"><span>High</span><small>{high_pct}%</small></div><div class="preview-bar"><i class="bar-high" style="width:{high_pct}%"></i></div>
              <div class="preview-bar-label"><span>Medium</span><small>{medium_pct}%</small></div><div class="preview-bar"><i class="bar-medium" style="width:{medium_pct}%"></i></div>
              <div class="preview-bar-label"><span>Low</span><small>{low_pct}%</small></div><div class="preview-bar"><i class="bar-low" style="width:{low_pct}%"></i></div>
            </div>
          </div>
          <div class="preview-recent-head"><span>RECENT ANALYSES</span><span>DISPLAY PREVIEW</span></div>
          <div class="preview-recent">{rows}</div>
        </div>
      </div>
    </div>
    """
