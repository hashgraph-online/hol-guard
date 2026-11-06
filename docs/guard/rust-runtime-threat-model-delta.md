# Native runtime hardening threat-model delta

Baseline reviewed: `release/3.0` at `0432719ee0d638443b7ef5208b4e16fc4ab70d80`.

Status: accepted baseline for the Rust hardening series.

## Assets

- Side-effect authorization and pause semantics.
- Model-visible output withholding and redaction.
- Secret material and sensitive local files.
- Approval, policy, rule, package, runtime, and daemon identities.
- Resident transport authentication material.
- Python daemon and Rust child availability.
- Durable receipts and command-activity ordering.

## Adversaries

- A compromised or prompt-injected AI agent running as the same operating-system user.
- A malicious local process racing the socket or port, flooding authentication, sending slow or malformed frames, or killing Guard processes.
- Malicious repository, web, issue, pull-request, log, MCP, package, or tool output attempting to become instructions.
- A local attacker replacing the runtime, manifest, policy snapshot, socket, port listener, or package files.
- An action intentionally designed to exhaust fallback processes, queues, memory, file descriptors, handles, threads, logs, or restart budgets.

## Trust boundaries

- Harness adapter to authenticated Python daemon.
- Python daemon to authenticated Rust resident process.
- Installed package and manifest to executable bytes.
- Native runtime to policy snapshot and rule contract.
- Filesystem path string to resolved file or directory identity.
- Tool output and repository/web content to model-visible reviewed output.

## Required mitigations

- Message-level mutual authentication on every resident transport.
- Request and response binding to protocol, request digest, runtime generation, rule digest, and policy snapshot.
- Hard caps and deadlines before allocation or expensive work.
- Non-blocking admission and bounded workers/queues.
- Bounded fallback and restart circuit breakers.
- Same-user local processes treated as untrusted.
- Native failure isolated from the Python daemon.
- Daemon failure produces deterministic fail-safe hook behavior.
- Security-monotonic Python/Rust composition.
- Package/source/rule/runtime identity verification and no `PATH` or runtime download.
- Privacy-safe diagnostics and rate-limited aggregate evidence.
- One authoritative implementation per migrated capability; replaced, unreachable, or untested Python duplicates are removed rather than retained as dormant fallback code.
- Every retained Python compatibility backend is named in the ownership manifest and exercised by an installed-artifact CI job.

## Abuse cases that must be tested

- Authentication flood, wrong proof, replay, partial proof, slow handshake.
- Oversized, truncated, trailing, duplicate-field, invalid UTF-8, deep, wide, and large-string frames.
- All workers busy, queue full, low file descriptors/handles, memory pressure, and response backpressure.
- Panic, abort, process kill, deadlock, stale endpoint, port squatting, socket poisoning, binary replacement, manifest replacement, and stale policy.
- Resident outage combined with 64 concurrent hook requests.
- Python daemon kill during each hook class.
- Flood-then-retry attempts intended to make Guard degrade into an allow.
- Secret read followed by encoded, archived, chunked, or indirect network transmission.
- Prompt-injection attempts to disable Guard or make untrusted text act as policy.
- Recursive deletion and destructive production database/infrastructure operations hidden behind wrappers, shell nesting, scripts, or environment indirection.
