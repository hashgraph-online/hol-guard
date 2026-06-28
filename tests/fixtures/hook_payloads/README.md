# Hook Payload Benchmark Fixtures

This directory contains benchmark fixtures for the HOL Guard fast hook review
performance tests. Fixtures are generated programmatically by
`scripts/bench_guard_hooks.py` — no static fixture files are stored to avoid
committing large or secret-containing content.

## Cases

| Name | Description | p95 Target |
|---|---|---|
| `small-post` | Pi PostToolUse 1KB output | ≤75ms |
| `read-ts-250kb` | Direct source ref for 250KB .ts file | ≤200ms |
| `read-md-1mb` | Direct source ref for 1MB .md file | ≤200ms |
| `stdout-1mb` | Shell stdout 1MB low-risk | ≤500ms |
| `secret-early` | Secret at byte ~100 | ≤25ms |
| `adversarial-json-1mb` | Nested JSON with many keys/items | ≤750ms |

## Running Benchmarks

```bash
python scripts/bench_guard_hooks.py \
  --harness pi \
  --daemon warm \
  --cases small-post,read-ts-250kb,read-md-1mb,secret-early \
  --iterations 50 \
  --json .artifacts/hook-bench-pi-warm.json
```

Threshold mode:

```bash
python scripts/bench_guard_hooks.py \
  --harness pi \
  --daemon warm \
  --cases small-post,read-ts-250kb,read-md-1mb,secret-early \
  --fail-p95 small-post=75ms,read-ts-250kb=200ms,read-md-1mb=200ms,secret-early=25ms
```

## Security

The benchmark script never prints raw secret fixture values. Secret fixtures
use known test patterns (e.g., `ghp_1234567890...`) that are detected by the
scanner but are not real credentials.
