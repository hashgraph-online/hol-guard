# Code review policy

## File-size guidance

Apply the repository's 500-line maintainability guideline to source-code files, not declarative JSON.

Never report a `*.json` file as too large based only on line count or file size, and never require JSON to be split solely to satisfy the 500-line guideline. This includes extension sources, fixtures, generated JSON, schemas, manifests, and contracts.

Continue reviewing JSON for correctness, security, schema validity, trust-boundary mistakes, contradictory or duplicated data, and unnecessary generated churn.

## Python runtime guidance

HOL Guard is moving its runtime from Python to Rust (`rust/crates/`). When a pull request adds or grows `*.py` code under `src/`, report one finding that asks whether the new runtime logic (command parsing, matching, classification, decisions, scanning, hashing, secure file I/O, hook handling, or other deterministic hot-path work) belongs in Rust instead.

Do not report tests and tooling (`tests/`, `ci/`, `scripts/`, `conftest.py`), deleted or shrinking Python, thin shims or glue that only call the native runtime, or fixes to existing Python that has no Rust equivalent yet.

Raise the finding as a question, not a blocker.
