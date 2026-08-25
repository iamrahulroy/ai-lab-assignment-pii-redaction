# Repository Instructions

## Environment preference

- Always create and use the dedicated Conda environment `pii-redactor` for this assignment.
- Never install dependencies into, modify, or run the project from Conda's `base` environment.
- Prefer reproducible commands through `conda run -n pii-redactor ...` and keep dependencies declared in `environment.yml`.

## Planning preference

- Store plans under `plans/`.
- Keep each plan concise and no longer than one page.

## Development workflow

- Work test-first using red-green-refactor.
- Preserve the supplied PDF and DOCX as immutable inputs.
- Do not report evaluation metrics unless they were produced by the checked-in evaluation process.
- Treat this as an assessed assignment: clearly explain the architecture, design decisions, alternatives, tradeoffs, limitations, false positives/negatives, and evaluation methodology alongside the implementation.
