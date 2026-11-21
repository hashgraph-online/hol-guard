# Rust Gauntlet VM worker protocol boundary

This is the fixed request and response syntax for the proposed Root-owned Linux ARM worker. The implemented parsers are [`worker_request.rs`](../ci/gauntlet-rs/crates/gauntlet-contracts/src/worker_request.rs) and [`worker_response.rs`](../ci/gauntlet-rs/crates/gauntlet-contracts/src/worker_response.rs). They validate data only; no Rust VM worker is installed or allowed to act on a parsed request yet. The [execution checklist](gauntlet-rust-execution-checklist.md) tracks durable receipts, leases, process identity, conformance and cutover separately.

The request is at most 1,024 bytes of bounded JSON. It has schema `hol-gauntlet-worker-request.v1` and exactly one of these shapes:

| Action | Required fields | Allowed effect |
| --- | --- | --- |
| `inspect` | `schema`, `action`, `source_sha`, `job_id` | Read a fixed Root-owned deployment declaration and report whether the exact source is staged. |
| `progress` | Same four fields | Read fixed progress/receipt paths without acquiring the active lease. Missing measurements are unavailable. |
| `reconcile` | Same four fields | Read the terminal receipt for the same job; missing or inconsistent evidence is unknown, never a replay instruction. |
| `run` | Those four fields plus `deployment_digest` | Attempt one source/deployment/job-bound execution only after Root-owned custody, lease and one-time started-marker checks. |

`source_sha` is 40 lowercase hexadecimal characters, `job_id` is 16, and the run-only `deployment_digest` is 64. Unknown fields, arbitrary command/path/profile selectors, duplicate JSON keys, missing pins and noncanonical identifiers fail before state access. The future host must obtain the deployment digest from an independent trusted channel. A digest carried in a candidate manifest or the request itself cannot pin the worker.

The `hol-gauntlet-worker-response.v1` syntax is limited to 2,048 bytes. Every response names the action, source SHA, job ID, worker-generation SHA-256 and one state. `inspect` admits `staged` or `unavailable`; `progress` admits `not-started`, `running`, `terminal`, `unknown` or `unavailable`; `reconcile` admits `terminal`, `unknown` or `unavailable`; `run` admits `running`, `terminal`, `unknown` or `unavailable`. `staged`, `running` and `terminal` carry a deployment SHA-256. `running` and `terminal` also carry the immutable started-marker SHA-256. `running` carries a kernel PID and process start tick. `terminal` carries a report SHA-256, exit code and bounded outcome (`passed`, `failed` or `invalid-evidence`). A `passed` outcome with a nonzero exit code is malformed.

The parser rejects unknown/misplaced fields, duplicate JSON keys, noncanonical identities and impossible action/state pairs. `bind_request` also compares the action, source and job to the original request, the worker generation to an independent pin, and any deployment digest to an independent pin. A missing terminal receipt is `unknown`; it never grants permission to retry. A parsed response is **not authenticated evidence**. The Root-owned worker must write an immutable, durable started marker before launching candidate execution, keep an exclusive lease, reject repeats after restart, and provide a signed or independently pinned terminal receipt. The host must authenticate the worker transport and separately verify marker/report bytes and process identity before trusting the state. None of those execution or custody rules is implemented by the parsers.

Only a separately reviewed worker artifact may interpret the request. Candidate source is inert input to the unprivileged builder; the worker must never import a candidate as Root. The existing passive release observer and optional PR gate remain unchanged during this protocol work.

The separate [`worker_receipt.rs`](../ci/gauntlet-rs/crates/gauntlet-evidence/src/worker_receipt.rs) reader handles the **existing Python worker** terminal JSON shape for shadow comparison. It checks independently supplied source/job/deployment/config pins and exact report bytes, but it cannot authenticate where those bytes came from, establish Root ownership or recompute control outcomes. Its result is always `execution_eligible: false`; it is not a substitute for the new durable Rust receipt protocol.
