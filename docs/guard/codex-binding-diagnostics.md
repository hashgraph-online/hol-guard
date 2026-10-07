# Codex binding diagnostics

Optional local diagnostics connect bridge ingress to a native worker result.
Capture stays off unless an evaluator explicitly creates a valid, unexpired
private v2 marker. Capture cannot supply native authority or an approval.

## Start a local capture

Use `initialize_capture_marker(guard_home, run_id=..., expires_at=...)` from
`codex_plugin_scanner.guard.codex_binding_capture`. Supply an existing absolute
Guard home with private ownership and permissions, a unique run ID and an
expiry within one hour. The initializer returns a `CaptureSession` on success
and `None` on refusal. It must not replace an existing marker. Interrupted
creation can leave a private partial marker; inspect the owned artifact before
explicit cleanup or starting another run.

The marker is `diagnostics/codex-binding-capture.v2.json`. Keep the directory
private with mode `0700` and marker with mode `0600`. The marker contains the
random per-run key. Do not log, serialize or export the marker or session.

Default limits are 128 records and 64 KiB of output per run; configured limits
cannot exceed these caps. Payload fingerprinting also has a 64 KiB canonical
input limit, a maximum depth of 64 and a 4,096-node limit. Smaller configured
record and byte limits apply to local joins too. Invalid, expired, unsupported
or unavailable capture state records nothing.

Writers retry an occupied file lock for up to 20 ms, then abandon that row.
Capture is best effort: an unmatched side can reflect contention, limits or
capture failure. It does not prove that the corresponding hook did not run.

The daemon submits native capture only after releasing the review fence and
checking the original deadline. Its separate writer retains at most eight
immutable tasks, each with at most 64 KiB of payload and receipt JSON. Queue
contention, a full queue, startup failure or shutdown drops the diagnostic;
review never waits for capture file I/O or for the queue to drain. Marker
validation, sealing and file writes run in that writer and remain default off.

Bridge capture is synchronous and consumes the existing hook budget. The lock
retry bound does not bound filesystem calls or total hook delivery time.
Neither capture route proves that every hook was recorded or meets a host
latency target. A missing row remains ambiguous.

## Verify locally

Read the private session with `read_capture_session(guard_home)`, then pass it
to `join_binding_records(records, capture_session=session)`. Keep JSONL input
within the capture limits.

V2 rows contain domain-separated HMAC fingerprints and a row MAC. Native
receipt fields are sealed with AES-GCM; the local join authenticates and opens
them before using the existing native receipt validator. Missing, wrong or
expired keys, mixed runs, modified rows and invalid receipts cannot bind.
Legacy v1 rows are rejected; they are not migrated or used as a fallback.

Keep marker and JSONL files local. Rows still contain bounded run and tool-use
identifiers. Share only reviewed, redacted aggregate results. A diagnostic
`bound` result describes local continuity; it does not supply native authority,
prove installed-host execution or replace an independently verified receipt.
