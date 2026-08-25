# PII Redaction Tool

This assignment provides a reproducible Python CLI that pseudonymizes PII in a
DOCX while preserving its OOXML structure. It always writes a separate output
bundle; the supplied DOCX and PDF are immutable inputs.

## Run it

Create or update the dedicated environment:

```bash
conda env update -n pii-redactor -f environment.yml --prune
```

Generate a Fernet key in a secure location outside the repository:

```bash
conda run -n pii-redactor python -c \
  'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' \
  > /secure/path/redaction_mapping.key
chmod 600 /secure/path/redaction_mapping.key
```

Run the redactor. `--output-dir` must not already exist because the directory
is published atomically:

```bash
conda run -n pii-redactor pii-redactor \
  --input "Red Herring Prospectus (3).docx" \
  --output-dir output-bundle \
  --config config/default.json \
  --seed 17 \
  --key-file /secure/path/redaction_mapping.key
```

The bundle contains:

- `redacted_prospectus.docx`
- `redaction_mapping.json.enc`
- `audit_report.json`

The key can instead be supplied through `PII_REDACTOR_MAPPING_KEY`. The seed
makes fake-value generation reproducible; it is not an encryption secret. The
mapping key is intentionally never committed or written to the audit. Automatic
unredaction is outside the assignment scope.

## Architecture

```text
immutable DOCX
  -> logical OOXML paragraph text
  -> Presidio Analyzer typed spans and scores
  -> deterministic thresholds and overlap resolution
  -> Presidio Anonymizer custom pseudonym operators
  -> document-scoped (type, normalized original) mapping
  -> exact replay of unambiguous known values missed by contextual NER
  -> run-preserving OOXML patches
  -> media, metadata, relationship, and hidden-text sanitization
  -> residual, image, ZIP, mapping, and hash validation
  -> atomic DOCX + encrypted mapping + PII-safe audit publication
```

[Presidio Analyzer](https://presidio.dataprivacystack.org/analyzer/) performs
detection; it does not invent replacements. Presidio Anonymizer calls our
custom operator, which obtains a type-appropriate fake from the document-scoped
registry. This keeps repeated values consistent without mutable global state.
The deny-list and regex extension mechanisms described in Presidio's
[deny-list tutorial](https://presidio.dataprivacystack.org/tutorial/01_deny_list/)
and [regex tutorial](https://presidio.dataprivacystack.org/tutorial/02_regex/)
informed the custom recognizer boundary.

Detection is hybrid:

- spaCy NER supplies `PERSON` and `ORGANIZATION` candidates.
- Validated/contextual recognizers cover emails, phones, addresses, SSNs,
  credit cards, DOBs, and IP addresses.
- PAN, Aadhaar, DIN, and CIN are document-specific extensions.
- `config/default.json` uses a document-specific Presidio deny list for the
  isolated DIN whose Word paragraph contains no identifying context.
- Deterministic thresholds, generic-organization filtering, and overlap
  precedence prevent nested email/phone/identifier detections.

The DOCX adapter edits `w:t`, deleted text, field text, and DrawingML text in
body paragraphs, tables, headers, footers, comments, footnotes/endnotes, text
boxes, and tracked changes. Replacements occupy the first touched run, so its
style is retained. Custom properties, reviewer metadata, revision IDs, and
external targets are scrubbed. All eight supplied images are replaced by
same-pixel-dimension neutral placeholders because identity cards, logos, and QR
codes may contain PII; OCR plus partial image redaction was intentionally not
added.

The design keeps CLI parsing, orchestration, detection, pseudonym generation,
DOCX adaptation, validation, encrypted storage, and atomic publication behind
narrow responsibilities. A new entity normally requires a recognizer,
threshold/precedence entry, and fake generator without changing the CLI or
publisher. For batch use, construct one Analyzer per worker and retain the
per-document registry boundary.

## Failure and security behavior

Outputs are built in a same-filesystem temporary directory. The DOCX is opened
and ZIP-tested; source/output hashes, removal of each representative mapped
literal, embedded image bytes and dimensions, and encrypted mapping round-trip
are checked before one atomic directory rename. Any detection, validation,
encryption, or publication error
returns non-zero and removes the stage. The safe audit contains only counts,
versions, hashes, warnings, and timings—not originals or replacements.

The encrypted mapping is sensitive even though it uses authenticated Fernet
encryption. Keep its key separately, restrict access, rotate it according to
the surrounding system's policy, and do not log decrypted records.

## Evaluation

Generate the report only through the checked-in evaluator:

```bash
conda run -n pii-redactor pii-redactor-evaluate \
  --annotations evaluation/annotations.json \
  --output evaluation_report.md
```

The annotation file contains a manually labelled, stratified sample derived
from named prospectus paragraphs and a separate synthetic dataset for SSN,
credit-card, DOB, IP, PAN, and Aadhaar categories absent from the source.
Exact entity scoring requires both type and character span to match. The report
also defines and computes token-label accuracy, F1/F2, per-type support, and
residual leakage. Real and synthetic results appear separately before the
secondary combined summary. See [evaluation_report.md](evaluation_report.md)
for the generated numbers.

Observed errors are informative: the real sample includes a director name that
spaCy labels as an organization, producing one type-level person false negative
and organization false positive while still covering the sensitive span. The
structured Indian postal-address pattern was broadened after an initial leakage
check found that the original street format was missed. Synthetic perfect scores
show recognizer-path coverage only; they are not evidence of production accuracy.

## Tradeoffs and limitations

- The labelled sample is intentionally small and is not statistically
  representative of the entire prospectus or other document domains.
- Company-name redaction reduces business readability but follows the explicit
  assignment requirement.
- NER can misclassify unusual names and organizations; regexes can miss unseen
  address/date formats or overmatch contextually similar text.
- DOB detection requires birth context so ordinary prospectus dates are not
  redacted, trading some recall for precision.
- Whole-image replacement maximizes privacy recall but removes benign branding
  and other useful pixels. There is no OCR claim or image-level metric.
- Longer fake values can change wrapping or pagination even though runs, tables,
  relationships, and styles are preserved.
- The residual scanner checks known mapped/annotated originals; it cannot prove
  the absence of PII that every recognizer and annotation missed.
- Development annotations and configured deny lists contain source values and
  need the same access controls as the input; a production deployment should
  keep them outside the distributable package.
- The checked-in validator performs structural validation. Canonical all-page
  rendering was attempted but unavailable because `soffice` is not installed;
  macOS Quick Look first-page review passed, but full visual review remains.

Pure regex was rejected because names and companies are too variable. Pure NER
was rejected because checksummed identifiers and contextual DOB rules benefit
from deterministic validation. An LLM/OCR pipeline could broaden recall but
adds nondeterminism, cost, data-governance risk, and a much larger evaluation
surface than this assignment requires.

## Tests

```bash
conda run -n pii-redactor pytest -q
```

The critical tests cover required entity detection, false-positive boundaries,
stable encrypted mappings, split-run/package sanitization, all-or-nothing CLI
failure behavior, metric arithmetic, immutable source hashes, and final bundle
integrity.
