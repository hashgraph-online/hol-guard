# `release/3.0` DX and performance baseline

Status: wave-zero baseline. Audience: execution-assurance gate reviewers. Source evidence snapshot: `origin/release/3.1` at `10348fd40fa53ef60d9363bb6c37591b8bb60a61`; release identity migrated to 3.0 and revalidated in PR #1901. Measured on macOS (Apple M4 Max), single process, synthetic workspace.

Privacy-safe aggregate measurements only. No raw user inbox data, command content, or machine paths are included; the corpus below uses synthetic commands.

## Hook evaluation latency

`evaluate_command()` end-to-end (parse → risk signals → composed action) measured over a synthetic corpus spanning benign, risky, compound, and failure-state commands (`git status`, `npm install lodash`, `rm -rf /tmp/x`, `cat ~/.aws/credentials`, `gh pr view`, `git push --force`, `curl … | sh`).

| Metric | 5-command corpus (n=300) | 7-command corpus (n=400) |
| --- | --- | --- |
| p50 | 0.11 ms | 0.129 ms |
| p95 | 0.17 ms | 0.192 ms |
| p99 | 0.20 ms | 0.283 ms |
| max | 0.30 ms | 0.378 ms |

Local evaluation is sub-millisecond per command; the hook path is not CPU/latency-bound on policy evaluation itself. End-to-end hook latency is dominated by process spawn and any daemon round-trip, not the evaluation core.

## Existing enforced budgets

- Daemon: 100 safe hook evaluations complete within a 10s budget (`tests/test_guard_daemon_perf.py:212-220`).
- Daemon threads: hook load does not grow the thread count beyond +5 over baseline (`test_guard_daemon_perf.py:195`).
- Module import: Guard module import stays under a 50 MB RSS budget (`test_guard_daemon_perf.py:224`).
- Pi harness hook: returns before the worker deadline; fallbacks stay inside the outer hook deadline and the host timeout (`tests/test_pi_hook_latency.py:73,156,199`).
- Receipt analytics: rollup analytics complete under 50 ms (`tests/test_guard_receipt_persistence.py`).

## Approval interruption

Approval interruption latency is governed by the approval grant, which is a 30-second transaction-local grant for the exact action/scope/subject/session nonce (see README). The evaluation path that raises an approval requirement is the same sub-millisecond `evaluate_command` path; user-facing interruption time is bounded by the approval-center round-trip, not by evaluation.

## Methodology

Measurements used `time.perf_counter()` around `evaluate_command()` in a synthetic temporary workspace (`--with-editable .` install), 300–400 iterations over a rotating synthetic corpus, results sorted for percentiles. No real user commands, files, or paths were read. Benchmark scripts were temporary and not committed.

## Notes

- These are single-process local numbers; CI platform matrix (macOS/Linux/Windows, Python 3.10–3.13) owns cross-platform performance evidence.
- This baseline does not authorize new performance budgets; it records current behavior and existing enforced budgets.
