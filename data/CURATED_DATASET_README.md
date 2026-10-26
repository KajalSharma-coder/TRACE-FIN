# TRACE//FIN curated candidate intake

`curated_candidates.csv` is a separate intake file. It is not the current
training dataset and is not consumed by the application or training scripts.
Do not edit `data/back.dataset.csv` to add candidates.

## Columns

- `Candidate_ID`: stable local identifier with no personal information.
- `Advertisement_Text`: the advertisement or awareness message, after approved
  redaction. Do not add raw account numbers, credentials, or personal contact
  details.
- `Risk_Label`: exactly `Safe` or `High Risk`.
- `Content_Subtype`: scam type or legitimate financial-content category.
- `Source_Provenance`: source, citation, URL/reference, or collection record.
- `Campaign_or_Template_Group`: stable campaign/template family identifier.
- `Collection_Date`: ISO date (`YYYY-MM-DD`).
- `Evidence`: short explanation or quoted evidence span supporting the label.
- `Review_Status`: use `Reviewed`, `Needs Review`, or `Rejected`.
- `Is_Synthetic`: `True` or `False`. Synthetic fixtures must never be presented
  as real-world evidence.
- `Assigned_Split`: optional `train`, `validation`, or `test` value. Leave blank
  until a frozen grouped split has been reviewed.

## Curation rules

Only rows marked `Reviewed`, with `Is_Synthetic=False`, no detected PII, no
conflicting labels, and complete provenance count toward training readiness.
Unreviewed, synthetic, ambiguous, or unverified rows remain visible in the
audit but are excluded from readiness counts.

Collect at least 60 independent templates per class as a provisional target,
with multiple scam types and legitimate financial-awareness categories. Aim
for at least five reviewed variants per template where variants genuinely
exist. Do not count name, account-number, punctuation, or minor wording
substitutions as independent templates.

Use documented real sources. Synthetic examples are permitted only as
explicitly labeled development fixtures. Never fabricate a source or evidence.

## Audit command

From the project root:

```text
python scripts/validate_training_dataset.py
python scripts/validate_training_dataset.py --input data/curated_candidates.csv --json
```

The command is read-only. It reports required-field errors, duplicates,
near-duplicates, conflicting labels, PII indicators, source/campaign leakage,
eligible template counts, and grouped train/validation/test readiness. It does
not merge data, start training, or modify model artifacts or the database.

The existing DistilBERT training guard remains authoritative. Passing this
intake audit is necessary but does not prove model quality or real-world
generalization.
