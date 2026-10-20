# Repository review guidance

## File-size review policy

The repository's 500-line maintainability guideline applies to source-code files, not declarative data files.

Do not raise line-count, file-length, "file too large", or split-the-file findings for `*.json` files. This includes command-extension sources under `contributions/command-sources/`, portable fixtures under `tests/fixtures/`, generated JSON, schemas, manifests, contracts, and other declarative JSON.

Large JSON files are expected when they enumerate command matchers, fixtures, schemas, or generated data. Review them for correctness, security, schema validity, duplication, malformed data, trust-boundary mistakes, and unnecessary generated churn, but never require splitting or shrinking them solely because of line count or file size.

Continue applying the 500-line guideline to source code where appropriate.

## Approval invariant

Every executable review must offer Allow once and Always allow, and every part of Guard must honor an approval until the user removes it or the command's hash changes. Read `docs/guard/approval-invariant.md` before changing approval tokens, retry bindings, scope contracts, saved decisions or the review card. A change that makes a supported review once-only, or drops Always allow for a supported execution route, breaks this invariant. Content-bound scripts without a working execution binding are explicitly unsupported: show the unavailable capability and verified recovery actions instead of approval buttons that cannot run the reviewed version. Inventory or a command-text hash cannot substitute for that binding. Findings about tighter binding without removing a supported choice are in scope.

## Python runtime review policy

HOL Guard is moving its runtime from Python to Rust (`rust/crates/`). Report new Python runtime logic under `src/`.

When a pull request adds or grows `*.py` code under `src/`, report one finding for the pull request that asks whether the new logic belongs in Rust instead. Runtime logic means command parsing, matching, classification, decisions, scanning, hashing, secure file I/O, hook handling, or other deterministic hot-path work. Name the likely crate when it is clear, and use `docs/guard/native-hook-data-plane-ownership.md` for what Rust already owns.

Do not report tests and tooling (`tests/`, `ci/`, `scripts/`, `conftest.py`), deleted or shrinking Python, thin shims or glue that only call the native runtime, parse arguments, or render its result, or fixes to existing Python that has no Rust equivalent yet.

Raise the finding as a question, not a blocker.
