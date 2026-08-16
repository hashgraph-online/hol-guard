# guard-command

`guard-command` is HOL Guard's side-effect-free native command model for the staged PreToolUse migration.

## Current authority

The crate is shadow-only. Python remains authoritative for PreToolUse policy decisions, approvals, receipts, and compatibility behavior.

## Exact subset

The `posix-simple-v1` parser may report `confidence = "exact"` only for bounded POSIX shell strings whose represented shell structure and tokenization match the Python reference model. The current exact subset covers ordinary argv-style commands, POSIX quoting and escaping, leading `NAME=value` assignments, PATH override detection, logical command groups, and pipelines.

## Conservative boundary

Command substitution, backticks, non-POSIX `$'...'` or `$"..."` quoting, heredocs, redirects, background jobs, shell control syntax, compound forms, transparent wrappers, nested shell evaluators, and command executors such as `xargs` are not partially interpreted. They return `confidence = "uncertain"` with no native segments until their semantics have dedicated parity tests.

The parser never executes input, expands variables, resolves executables, reads shell startup files, or performs network I/O. Hard limits match the Python command model: 32 KiB command input, 128 segments, and 2,048 tokens.

Native PreToolUse authority must not be enabled solely because this crate exists. Exact Python/Rust differential coverage and fail-closed hook integration are separate rollout gates.
