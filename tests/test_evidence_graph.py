from src.evidence_graph import build_evidence_graph, make_3d_figure


def _analysis(text="", rules=None, **extra):
    return {
        "final_verdict": "HIGH RISK", "final_score": 86,
        "explanation": "Existing verdict explanation.",
        "matched_rules": rules or [], "evidence": [], "urls": [],
        "emails": [], "phone_numbers": [], "payment_identifiers": [],
        **extra,
    }


def test_evidence_graph_extracts_actual_rules_entities_and_url_relationships():
    text = "HDFC Bank urgent KYC verification at https://hdfc-secure.example/verify"
    result = _analysis(
        text,
        rules=[{"category": "KYC Evasion & Verification Bypass",
                "rule_name": "KYC request", "evidence": "Request to update KYC immediately"}],
        urls=["https://hdfc-secure.example/verify"],
        url_model_results=[{"url": "https://hdfc-secure.example/verify",
                            "available": True, "prediction": "Phishing", "phishing_probability": .92}],
    )
    graph = build_evidence_graph(result, text=text)
    labels = {node["label"] for node in graph["nodes"]}
    assert "Bank name mentioned" in labels
    assert "KYC / verification request" in labels
    assert "Suspicious URL" in labels
    assert any(edge["label"] == "uses host" for edge in graph["edges"])
    assert all(node["id"] for node in graph["nodes"])
    assert len({node["id"] for node in graph["nodes"]}) == len(graph["nodes"])


def test_node_ids_are_stable_and_sensitive_values_are_redacted():
    analysis = _analysis(
        rules=[{"category": "Sensitive banking details", "evidence": "Send CVV: 123"}],
        phone_numbers=["+1 415 555 0136"],
    )
    first = build_evidence_graph(analysis, text="Call +1 415 555 0136")
    second = build_evidence_graph(analysis, text="Call +1 415 555 0136")
    assert [n["id"] for n in first["nodes"]] == [n["id"] for n in second["nodes"]]
    all_values = " ".join(n["value"] for n in first["nodes"])
    assert "123" not in all_values
    assert "415 555 0136" not in all_values


def test_empty_evidence_has_only_central_node_and_no_fake_edges():
    result = {"final_verdict": "INSUFFICIENT EVIDENCE", "final_score": None}
    graph = build_evidence_graph(result)
    assert graph["evidence_count"] == 0
    assert graph["edges"] == []
    assert len(graph["nodes"]) == 1
    assert graph["high_risk_count"] == 0


def test_graph_rebuilds_for_a_different_advertisement():
    first = build_evidence_graph(_analysis(rules=[{"category": "Urgency", "evidence": "Act now"}]))
    second = build_evidence_graph({"final_verdict": "LOW RISK", "final_score": 0,
                                  "matched_rules": [], "urls": []},
                                 text="Routine bank interest rate notice")
    assert first["central_id"] != second["central_id"]
    assert first["nodes"] != second["nodes"]


def test_risk_aggregation_uses_existing_assessment_without_recomputing():
    graph = build_evidence_graph(_analysis(rules=[{"category": "Account Sale", "evidence": "Sell accounts"}]))
    assert graph["risk_score"] == 86
    assert graph["classification"] == "HIGH RISK"
    assert graph["high_risk_count"] == 2  # central score tier and actual rule match


def test_shared_phone_is_added_only_when_another_real_record_supports_it():
    current = _analysis(phone_numbers=["+1 415 555 0136"])
    graph = build_evidence_graph(
        current,
        related_records=[{"record_id": "TF-123", "phone_numbers": ["+1 415 555 0136"]}],
    )
    shared = next(node for node in graph["nodes"] if node["label"] == "Shared phone number")
    assert shared["value"] == "•••36"
    assert "TF-123" in shared["reason"]

    no_match = build_evidence_graph(current, related_records=[])
    assert not any(node["label"] == "Shared phone number" for node in no_match["nodes"])


def test_legitimate_financial_ad_has_no_invented_suspicious_entities():
    text = "SBI Home Loan: apply online through your branch. Terms and conditions apply."
    graph = build_evidence_graph({"final_verdict": "LOW RISK", "final_score": 0,
                                  "matched_rules": [], "urls": []}, text=text)
    assert [n["label"] for n in graph["nodes"]] == ["LOW RISK", "Bank name mentioned"]
    assert "unverified" in graph["nodes"][1]["reason"]


def test_3d_plot_contains_interactive_node_trace_and_connections():
    graph = build_evidence_graph(_analysis(rules=[{"category": "Urgency", "evidence": "Act now"}]))
    figure = make_3d_figure(graph)
    assert any(trace.type == "scatter3d" and "markers" in (trace.mode or "") for trace in figure.data)
    assert len(figure.data) >= 2
