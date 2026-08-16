# ADR 0009: Native child and Python daemon critical-failure behavior

Baseline reviewed: `release/3.0` at `0432719ee0d638443b7ef5208b4e16fc4ab70d80`.

Status: accepted for implementation on the 3.0 prerelease train. This ADR does not change the native source default.

## Decision

The Python daemon remains the canonical control plane. The Rust runtime remains an isolated contained child. A Rust panic or abort must not terminate or retire a healthy Python daemon.

Native health is explicit: `disabled`, `starting`, `healthy`, `degraded`, `recovering`, `overloaded`, `circuit_open`, and `incompatible`.

A native failure follows a capability-specific bounded sequence while the Python daemon is healthy:

1. Before authority cutover, use the named Python reference backend only when it is an explicit supported mode, capacity and the hook deadline permit, and CI exercises that exact fallback.
2. After authority cutover, attempt one bounded invocation of the same verified Rust binary and then return a fail-safe pause or output block. Do not silently revive a duplicate Python implementation.
3. Restart the native child asynchronously under a single-flight supervisor.
4. Re-attest package version, source SHA, executable digest, protocol, target, rule digest, and policy snapshot before returning to service.
5. Open a circuit after a bounded failure threshold. Stop restart, one-shot, and Python-process storms.
6. Close the circuit only after a successful half-open self-test and health probe.

A Python daemon failure is a critical protection state:

- PostToolUse output remains withheld or blocked.
- Mutating, network-capable, secret-capable, destructive, package-executing, process-control, policy-tampering, and uncertain PreToolUse actions pause.
- Only the ratified exact emergency-safe profile may continue, and only when its package, rule, and policy identities are authenticated and current.
- Empty or malformed hook responses must never be interpreted as successful tool execution.

## Recovery ownership

Only one process may reserve daemon or native restart ownership for a Guard home. Restarts use bounded exponential backoff with jitter. Repeated failure opens a circuit. Health, shutdown, doctor, repair, and rollback remain available during overload or circuit-open states.

## Privacy

Health and lifecycle evidence may include only enumerated state, failure category, aggregate counters, latency buckets, queue buckets, generation number, and version/digest match booleans. Raw commands, prompts, output, paths, destinations, environment values, database strings, secrets, tokens, proofs, and arbitrary exception text are forbidden.
