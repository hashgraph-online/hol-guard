# Rust Authority Migration Batch 1

Base branch: `release/3.0`

Invariant: supported command `PreToolUse` decisions are produced only by the Rust runtime. Python may transport or render a native result, coordinate approval, and persist evidence, but it may not parse, classify, lower, replace, or synthesize the semantic decision. There is no `strict` mode. Rust is the default authority. When the native runtime is present or forced, native failure fails closed.

- [x] T001 Pin the `release/3.0` PreToolUse authority contract to `pre-tool --stdin` and resident `pre_tool_use`.
- [x] T002 Add `evaluate_pre_tool` in `guard-command` with allow, review, and fail-closed block floors.
- [x] T003 Transport native PreToolUse results through Python without semantic re-evaluation.
- [x] T004 Make Rust the default command PreToolUse backend in the daemon fast path and CLI policy floor.
- [x] T005 Fail closed when a present or forced native runtime cannot decide, and keep non-command PreToolUse on the existing CLI path.
