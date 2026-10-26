# Python runtime review policy

HOL Guard is moving its runtime from Python to Rust (`rust/crates/`). Report new Python runtime logic under `src/`.

When a pull request adds or grows `*.py` code under `src/`, report one finding for the pull request that asks whether the new logic belongs in Rust instead. Runtime logic means command parsing, matching, classification, decisions, scanning, hashing, secure file I/O, hook handling, or other deterministic hot-path work. Name the likely crate when it is clear, and use `docs/guard/native-hook-data-plane-ownership.md` for what Rust already owns.

Do not report:

- tests and tooling: `tests/`, `ci/`, `scripts/`, and `conftest.py`;
- deleted or shrinking Python;
- thin shims or glue that only call the native runtime, parse arguments, or render its result; or
- fixes to existing Python that has no Rust equivalent yet.

Raise the finding as a question, not a blocker. Do not port the code to Rust as an automatic repair.
