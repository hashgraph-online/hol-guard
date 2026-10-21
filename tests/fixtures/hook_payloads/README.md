# Hook Payload Benchmark Fixtures

This directory documents benchmark cases for the HOL Guard fast hook review
performance tests. The Python-oracle benchmark driver
(`scripts/bench_guard_hooks.py`) was retired with the Python hook oracle; no
static fixture files are stored to avoid committing large or secret-containing
content.

## Cases

| Name | Description | p95 Target |
|---|---|---|
| `small-post` | Pi PostToolUse 1KB output | ≤75ms |
| `read-ts-250kb` | Direct source ref for 250KB .ts file | ≤200ms |
| `read-md-1mb` | Direct source ref for 1MB .md file | ≤200ms |
| `stdout-1mb` | Shell stdout 1MB low-risk | ≤500ms |
| `secret-early` | Secret at byte ~100 | ≤25ms |
| `adversarial-json-1mb` | Nested JSON with many keys/items | ≤750ms |

## Security

Benchmark fixtures never include raw secret values. Secret fixtures use known
test patterns (e.g., `ghp_1234567890...`) that trip the native scanner but are
not real credentials.
