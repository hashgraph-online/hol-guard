# Python runtime policy

HOL Guard is moving its runtime from Python to Rust (`rust/crates/`).

When a pull request adds or grows `*.py` code under `src/`, report one finding asking whether the new runtime logic (command parsing, matching, classification, decisions, scanning, hashing, secure file I/O, hook handling, or other hot-path work) belongs in Rust instead. Do not report `tests/`, `ci/`, `scripts/`, deleted or shrinking Python, thin shims that only call the native runtime, or fixes to existing Python that has no Rust equivalent yet. Raise it as a question, not a blocker.
