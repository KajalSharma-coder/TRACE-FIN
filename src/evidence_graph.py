"""Structured, redacted evidence graph derived only from analysis output."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

import plotly.graph_objects as go

from src.browser_analysis import redact_sensitive_text


_COLORS = {
    "advertisement": "#35d5ff", "url": "#a78bfa", "domain": "#60a5fa",
    "bank": "#22d3ee", "card": "#fb7185", "phone": "#fbbf24",
    "email": "#f59e0b", "urgent": "#fb7185", "kyc": "#c084fc",
    "payment": "#f97316", "rule": "#34d399", "image": "#94a3b8",
}
_ICONS = {"advertisement": "📢", "url": "🔗", "domain": "🌐", "bank": "🏦",
          "card": "💳", "phone": "📞", "email": "✉️", "urgent": "⏱️",
          "kyc": "🪪", "payment": "💸", "rule": "⚠️", "image": "🖼️"}
_SECRET = re.compile(
    r"\b(?:otp|cvv|cvc|pin|password|passcode|session\s+token|access\s+token)\b"
    r"(?:\s+(?:is|:|=))?\s*[:=#-]?\s*[A-Za-z0-9-]{2,}", re.I
)
_BANK_NAMES = (
    "State Bank of India", "SBI", "HDFC Bank", "ICICI Bank", "Axis Bank",
    "Kotak Mahindra Bank", "Punjab National Bank", "PNB", "Bank of Baroda",
    "Canara Bank", "Union Bank of India", "IDFC First Bank", "Yes Bank",
    "IndusInd Bank", "Federal Bank", "RBL Bank", "Paytm Payments Bank",
)


def _safe_value(value: object, kind: str = "") -> str:
    raw = str(value or "")
    if kind == "phone":
        digits = re.sub(r"\D", "", raw)
        return f"•••{digits[-2:]}" if len(digits) >= 4 else "[REDACTED PHONE]"
    if kind == "email" and "@" in raw:
        local, domain = raw.rsplit("@", 1)
        return f"{local[:1]}***@{domain}"
    text = redact_sensitive_text(raw)
    text = _SECRET.sub("[REDACTED SECRET]", text)
    # Mask likely numeric account/card values if another detector didn't catch them.
    text = re.sub(r"(?<!\w)(?:\d[ -]?){8,19}(?!\w)", "[REDACTED FINANCIAL NUMBER]", text)
    return text[:500]


def _node_id(kind: str, label: str, value: str) -> str:
    digest = hashlib.sha256(f"{kind}|{label}|{value}".encode("utf-8")).hexdigest()[:12]
    return f"{kind}-{digest}"


def build_evidence_graph(
    analysis: dict | None,
    *,
    text: str = "",
    source_type: str = "Advertisement text",
    source_meta: dict | None = None,
    browser_result: dict | None = None,
    related_records: list[dict] | None = None,
) -> dict:
    """Build stable nodes/edges from rule matches and actual pipeline fields."""
    analysis = analysis or {}
    source_meta = source_meta or {}
    browser_result = browser_result or {}
    nodes: list[dict] = []
    edges: list[dict] = []
    index: dict[str, str] = {}

    def add(kind: str, label: str, value: object, source: str, reason: str,
            *, risk: str = "medium", confidence: float | None = None,
            private_identity: str | None = None) -> str:
        clean_value = _safe_value(value, kind)
        key = (kind, label, private_identity or clean_value)
        if key in index:
            return index[key]
        node_id = _node_id(*key)
        index[key] = node_id
        nodes.append({
            "id": node_id, "type": kind, "label": label, "value": clean_value,
            "icon": _ICONS.get(kind, "🔎"),
            "source": source, "reason": reason, "risk": risk,
            "confidence": confidence, "related_ids": [],
        })
        return node_id

    score = analysis.get("final_score")
    classification = analysis.get("final_verdict") or "Advertisement analyzed"
    central_id = add("advertisement", classification, "Suspicious Financial Advertisement",
                     source_type, analysis.get("explanation") or "Central advertisement under review.",
                     risk="high" if isinstance(score, (int, float)) and score >= 70 else "medium")

    def connect(a: str, b: str, label: str) -> None:
        if a == b or any(e["source"] == a and e["target"] == b and e["label"] == label for e in edges):
            return
        edges.append({"source": a, "target": b, "label": label})
        nodes_by_id = {n["id"]: n for n in nodes}
        nodes_by_id[a]["related_ids"].append(b)
        nodes_by_id[b]["related_ids"].append(a)

    rules = analysis.get("matched_rules") or []
    for rule in rules:
        category = str(rule.get("category") or "Financial indicator")
        detail = rule.get("evidence") or rule.get("rule_name") or category
        lowered = f"{category} {rule.get('rule_name', '')} {detail}".lower()
        if "kyc" in lowered or "verification" in lowered:
            kind, label, edge = "kyc", "KYC / verification request", "requests"
        elif any(s in lowered for s in ("card", "cvv", "pin", "otp", "account detail")):
            kind, label, edge = "card", "Banking details requested", "requests"
        elif any(s in lowered for s in ("urgency", "urgent", "threat", "suspension", "blocked")):
            kind, label, edge = "urgent", "Urgent or threatening language", "contains"
        elif any(s in lowered for s in ("payment", "fee", "upi", "crypto")):
            kind, label, edge = "payment", "Payment instruction", "requests"
        else:
            kind, label, edge = "rule", category, "contains"
        node = add(kind, label, detail, "Existing rule engine", category,
                   risk="high", confidence=None)
        connect(central_id, node, edge)

    # Entity mentions are reported as mentions, never as verified affiliation.
    for bank in _BANK_NAMES:
        if re.search(rf"(?<!\w){re.escape(bank)}(?!\w)", text, re.I):
            node = add("bank", "Bank name mentioned", bank, "Advertisement text",
                       "The name appears in the submitted text; affiliation or authorization is unverified.")
            connect(central_id, node, "mentions")

    for value in analysis.get("phone_numbers") or []:
        node = add("phone", "Phone number", value, "Existing identifier extraction",
                   "Phone-like contact value extracted from the advertisement.")
        connect(central_id, node, "contains")
    for value in analysis.get("emails") or []:
        node = add("email", "Email address", value, "Existing identifier extraction",
                   "Email address extracted from the advertisement.")
        connect(central_id, node, "contains")
    for value in analysis.get("payment_identifiers") or []:
        node = add("payment", "Payment identifier", value, "Existing identifier extraction",
                   "Payment-like identifier extracted; ownership is unverified.", risk="high")
        connect(central_id, node, "contains")

    urls = list(analysis.get("urls") or [])
    if browser_result.get("url"):
        urls.append(browser_result["url"])
    urls.extend(source_meta.get("final_url", []) if isinstance(source_meta.get("final_url"), list)
                else ([source_meta["final_url"]] if source_meta.get("final_url") else []))
    url_results = analysis.get("url_model_results") or source_meta.get("url_model_results") or []
    if isinstance(url_results, dict):
        url_results = [url_results]
    for url in dict.fromkeys(str(u) for u in urls if u):
        result = next((r for r in url_results if r.get("url") == url or r.get("original_url") == url), {})
        prediction = str(result.get("prediction") or "").lower()
        suspicious = "phish" in prediction or "malicious" in prediction
        node = add("url", "Suspicious URL" if suspicious else "Advertisement URL", url,
                   "URL phishing model" if result else "Advertisement text",
                   (f"Existing URL model classification: {result.get('prediction')}" if result else
                    "URL observed in the submitted content; no URL model result is available."),
                   risk="high" if suspicious else "medium" if result else "low",
                   confidence=result.get("phishing_probability"))
        connect(central_id, node, "contains")
        try:
            host = urlsplit(url if "://" in url else "https://" + url).hostname
        except ValueError:
            host = None
        if host:
            domain = add("domain", "Domain", host, "URL syntax",
                         "Hostname parsed from the URL. Reputation and ownership were not verified.",
                         risk="high" if suspicious else "low")
            connect(node, domain, "uses host")

    # Cross-record matches use exact stored indicators and ignore synthetic samples.
    related_records = related_records or []
    current_record_id = analysis.get("record_id")
    current_fields = {
        "phone": set(str(v).strip().casefold() for v in analysis.get("phone_numbers") or []),
        "url": set(str(v).strip().casefold() for v in analysis.get("urls") or []),
    }
    record_fields = {"phone": "phone_numbers", "url": "urls"}
    for kind, field in record_fields.items():
        shared: dict[str, list[str]] = {}
        for record in related_records:
            if record.get("is_synthetic") or record.get("record_id") == current_record_id:
                continue
            for item in record.get(field) or []:
                normalized = str(item).strip().casefold()
                if normalized in current_fields[kind] and normalized:
                    shared.setdefault(normalized, []).append(str(record.get("record_id", "saved record")))
        for value, record_ids in shared.items():
            label = "Shared phone number" if kind == "phone" else "Shared URL"
            node = add(kind, label, value, "Saved advertisement records",
                       f"Exact indicator match in {len(set(record_ids)) + 1} non-synthetic advertisements; records: "
                       + ", ".join(sorted(set(record_ids))[:5]),
                       risk="high", private_identity=value)
            connect(central_id, node, "shares indicator with")

    # OCR is evidence of text, not visual authenticity or logo verification.
    if source_type == "Image OCR":
        node = add("image", "Image text (OCR)", "OCR text analyzed; logo authenticity not assessed",
                   "Local OCR", "Text recognition was used; fake-logo or screen authenticity detection is unavailable.", risk="low")
        connect(central_id, node, "text extracted from")

    return {"nodes": nodes, "edges": edges, "central_id": central_id,
            "risk_score": score, "classification": classification,
            "url_models": url_results, "advertisement_result": analysis,
            "evidence_count": max(0, len(nodes) - 1),
            "high_risk_count": sum(n["risk"] == "high" for n in nodes)}


def make_3d_figure(graph: dict, selected_ids: set[str] | None = None) -> go.Figure:
    """Create an interactive Plotly 3D graph with real node labels and edges."""
    nodes, edges = graph.get("nodes", []), graph.get("edges", [])
    selected_ids = selected_ids or set()
    coords: dict[str, tuple[float, float, float]] = {}
    center = next((n for n in nodes if n["id"] == graph.get("central_id")), None)
    if center:
        coords[center["id"]] = (0, 0, 0)
    spoke_count = max(1, len(nodes) - (1 if center else 0))
    others = [n for n in nodes if not center or n["id"] != center["id"]]
    for i, node in enumerate(others):
        angle = (2 * 3.141592653589793 * i / spoke_count) + 0.33
        coords[node["id"]] = (2.8 * __import__("math").cos(angle),
                              2.8 * __import__("math").sin(angle),
                              ((i % 3) - 1) * 1.15)

    fig = go.Figure()
    for edge in edges:
        a, b = coords.get(edge["source"]), coords.get(edge["target"])
        if not a or not b:
            continue
        related = bool(selected_ids & {edge["source"], edge["target"]})
        mid_x, mid_y = (a[0] + b[0]) / 2, (a[1] + b[1]) / 2
        control = (mid_x - .14 * mid_y, mid_y + .14 * mid_x,
                   (a[2] + b[2]) / 2 + .32)
        curve = []
        for step in range(13):
            t = step / 12
            curve.append(tuple((1-t)**2 * a[i] + 2 * (1-t) * t * control[i] + t**2 * b[i]
                               for i in range(3)))
        fig.add_trace(go.Scatter3d(x=[p[0] for p in curve],
                                   y=[p[1] for p in curve],
                                   z=[p[2] for p in curve],
                                   mode="lines", line={"color": "#31d9ff" if related else "#34536f",
                                                        "width": 4 if related else 2},
                                   hoverinfo="text", text=[edge["label"]] * 3,
                                   showlegend=False))

    color_map = {"high": "#fb5475", "medium": "#ffba55", "low": "#30d6c3"}
    # Scatter3d marker points expose Plotly's native click/selection and camera controls.
    xs, ys, zs, labels, colors, sizes, custom = [], [], [], [], [], [], []
    for node in nodes:
        x, y, z = coords[node["id"]]
        active = not selected_ids or node["id"] in selected_ids or any(
            node["id"] in selected_ids and edge["source"] == node["id"] for edge in edges)
        xs.append(x); ys.append(y); zs.append(z)
        labels.append(f"{node['icon']} {node['label']}")
        color = _COLORS.get(node["type"], color_map[node["risk"]])
        if selected_ids and node["id"] not in selected_ids:
            color = f"rgba({int(color[1:3],16)},{int(color[3:5],16)},{int(color[5:7],16)},0.22)"
        colors.append(color)
        sizes.append(29 if node["id"] in selected_ids else
                     25 if node["id"] == graph.get("central_id") else 18)
        custom.append([node["id"], node["value"], node["source"], node["reason"]])
    fig.add_trace(go.Scatter3d(
        x=xs, y=ys, z=zs, mode="markers", hoverinfo="skip",
        marker={"size": [size + 12 for size in sizes], "color": colors,
                "opacity": .20, "symbol": "circle", "line": {"width": 0}},
        showlegend=False,
    ))
    fig.add_trace(go.Scatter3d(
        x=xs, y=ys, z=zs, mode="markers+text", text=labels, textposition="top center",
        customdata=custom, hovertemplate="<b>%{text}</b><br>%{customdata[1]}<extra></extra>",
        marker={"size": sizes, "color": colors, "opacity": .95, "symbol": "circle",
                "line": {"color": "#e0fbff", "width": 1.5}, "showscale": False},
        showlegend=False,
    ))
    fig.update_layout(
        height=610, margin={"l": 0, "r": 0, "t": 14, "b": 0},
        paper_bgcolor="#07111f", plot_bgcolor="#07111f",
        font={"color": "#dbeafe", "family": "Inter, sans-serif"},
        scene={"bgcolor": "#07111f", "xaxis": {"visible": False},
               "yaxis": {"visible": False}, "zaxis": {"visible": False},
               "camera": {"eye": {"x": 1.45, "y": 1.45, "z": 1.12}},
               "aspectmode": "data"},
        clickmode="event+select", dragmode="orbit",
    )
    return fig
