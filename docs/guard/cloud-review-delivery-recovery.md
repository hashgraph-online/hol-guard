# Cloud Review delivery and consent recovery

A connection and saved Cloud Review consent are separate from working delivery.
Review delivery is ready when both the decision worker (`running`) and event
upload worker (`sync_running`) are running. A successful daemon refresh response
alone does not establish readiness.

`hol-guard cloud-review enable --json` saves consent and requeues eligible pending
requests. If either worker cannot start, it returns exit code 2 with
`status: enabled_worker_retry_required`, `capability_enabled: true`, and
`delivery_ready: false`. The saved consent remains available. Restore the daemon
with `hol-guard daemon repair`, then retry `hol-guard cloud-review enable --json`.
An ordinary retry preserves the valid consent identity and its expiry, so already
pending requests do not lose their authority merely because delivery was retried.

Use `hol-guard cloud-review enable --renew` when you intend to replace consent and
start a new expiry period. `--expires-in-days` applies when issuing or renewing
consent. Renewal changes the consent identity; a Cloud decision bound to the old
identity must be refreshed before it can apply. An unused expiry option does not
block delivery recovery while existing consent remains valid; new or explicitly
renewed consent still requires an expiry from 1 through 365 days.

In local Settings, **Restore Cloud Review** retries delivery with the existing
authorization and expiry. **Renew authorization** opens a separate confirmation
to start a new 30-day period. Both actions require workspace/source checks and
the existing local approval proof when configured. Previously unassigned events remain excluded unless
their checkbox is explicitly selected. Turning off review still revokes consent
through the existing disable command or dashboard action.

The worker retains its wake signal and jittered error backoff. Invalid timing
configuration falls back to the defaults below and records the variable name in a
warning. The supplied value is excluded from the warning.

| Environment variable | Default | Accepted range |
| --- | ---: | ---: |
| `GUARD_CLOUD_REVIEW_POLL_INTERVAL` | 30 seconds | 0.1–3600 seconds |
| `GUARD_CLOUD_REVIEW_ERROR_BACKOFF` | 30 seconds | 0.1–3600 seconds |
| `GUARD_CLOUD_REVIEW_ERROR_BACKOFF_BASE` | 1 second | 0.1–3600 seconds |

The initial backoff is capped at the configured maximum. Zero, negative,
non-finite, malformed, and out-of-range values cannot create a polling loop with
no delay or prevent daemon startup. Stop and wake signals interrupt even the
largest accepted wait.
