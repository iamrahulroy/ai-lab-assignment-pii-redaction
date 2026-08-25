# PII Redaction Tool

A reproducible Python CLI that reads the supplied DOCX, replaces detected PII
with consistent fake alternatives, and writes a separate output bundle. The
source DOCX and assignment PDF are never modified.

## Run

```bash
conda env update -n pii-redactor -f environment.yml --prune

conda run -n pii-redactor python -c \
  'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' \
  > /secure/path/redaction_mapping.key
chmod 600 /secure/path/redaction_mapping.key

conda run -n pii-redactor pii-redactor \
  --input "Red Herring Prospectus (3).docx" \
  --output-dir output-bundle \
  --config config/default.json \
  --seed 17 \
  --key-file /secure/path/redaction_mapping.key
```

`--output-dir` must not already exist. The generated bundle contains:

- `redacted_prospectus.docx`
- `redaction_mapping.json.enc`
- `audit_report.json`

## Approach

```text
DOCX OOXML text
  -> Presidio Analyzer (NER, regex, context, deny list)
  -> deterministic score/overlap resolution
  -> Presidio Anonymizer with custom fake-value operator
  -> document-scoped consistent mapping
  -> known-value replay
  -> OOXML patching and sanitization
  -> validation, encryption, and atomic publication
```

The hybrid detector uses spaCy NER for full names and companies; Presidio and
custom recognizers for emails, phones, addresses, SSNs, credit cards, DOBs, and
IP addresses; and document-specific recognizers for PAN, Aadhaar, DIN, and CIN.
An isolated DIN without local Word-paragraph context is configured through a
Presidio deny list. See the Presidio [Analyzer](https://presidio.dataprivacystack.org/analyzer/),
[deny-list](https://presidio.dataprivacystack.org/tutorial/01_deny_list/), and
[regex](https://presidio.dataprivacystack.org/tutorial/02_regex/) documentation.

Mappings are keyed by `(entity type, normalized original)`, so formatting or
case variants reuse the same deterministic fake. A second pass replays safe,
unambiguous known values where contextual NER was inconsistent. The DOCX
adapter preserves runs and styles where possible, scrubs metadata and external
links, and replaces all embedded images with same-dimension neutral
placeholders because images may contain unscanned PII.

The original-to-fake mapping is Fernet-encrypted with `0600` permissions. Keep
the key outside the repository; the seed controls reproducibility and is not an
encryption secret. Artifacts are built in a temporary directory and published
with one rename only after DOCX, hash, mapping, image, and leakage checks pass.

## Evaluation

Generate the checked-in report with:

```bash
conda run -n pii-redactor pii-redactor-evaluate \
  --annotations evaluation/annotations.json \
  --output evaluation_report.md
```

The evaluator uses exact entity type and character-span matching and reports
TP/FP/FN, precision, recall, F1/F2, token-label accuracy, and residual leakage.
Real prospectus annotations and synthetic cases for types absent from the source
are reported separately. The real sample achieved `0.8750` precision,
`0.8750` recall, and `0.9423` token accuracy; the secondary combined result was
`0.9286` precision/recall and `0.9677` token accuracy. These figures come only
from [evaluation_report.md](evaluation_report.md); the small labelled sample is
not statistically representative of the full prospectus.

## Tradeoffs and limitations

- The real sample has one director name classified as an organization: the
  sensitive span is redacted, but its entity type is wrong.
- NER can miss unusual names/companies; regexes can miss new address or date
  formats or overmatch similar business text. DOBs require birth context to
  avoid redacting ordinary prospectus dates.
- Company redaction and whole-image replacement improve privacy recall but
  reduce document usefulness. Longer fake values can also change wrapping.
- Validation checks known mappings and annotations; it cannot prove that PII
  missed by every recognizer is absent. Images are replaced without OCR.
- Structural DOCX and first-page Quick Look checks passed. Full all-page visual
  rendering was unavailable because `soffice` was not installed.
- Annotation and deny-list files contain source values and require the same
  access controls as the input in a production deployment.

## Tests

```bash
conda run -n pii-redactor pytest -q
```

Critical tests cover required PII detection, false-positive boundaries,
consistent encrypted mappings, split-run/hidden OOXML sanitization, immutable
source hashes, metric arithmetic, atomic failure handling, and final bundle
integrity.
