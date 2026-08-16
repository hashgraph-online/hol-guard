# Takeaway prompt: continue HOL Guard MDM Cloud hardening

Work only from the current `release/3.0` MDM contracts and the multi-device integration lab. Preserve the boundary between provider-neutral correctness and native certification.

For every change:

1. Identify the exact security invariant and failure boundary.
2. Add or update a strict schema before adding authority.
3. Bind Cloud configuration, evidence, and remediation to workspace, device, installation generation, revision, and cryptographic identity.
4. Keep desired state declarative. Never add arbitrary commands, scripts, shell text, URLs, credentials, or open-ended parameter bags.
5. Preserve monotonic request and health sequences, per-device predecessor hashes, durable acknowledgements, and offline outboxes.
6. Keep the last known good local policy active during Cloud, proxy, database, or provider failure.
7. Add a deterministic fault and a named orchestrator assertion for every regression.
8. Run focused contract/schema tests, the real-HTTP in-process integration, and the Docker Compose lab.
9. Emit bounded, redacted evidence and always tear down containers and volumes.
10. Leave Apple, Windows, and commercial-provider results as `not-evaluated` until executed on the actual platform or provider.

Definition of done:

- The invariant is enforced in code, not only documented.
- Positive, negative, replay, crash, restart, concurrency, and privacy paths are covered.
- No local or Cloud path can weaken policy because management is offline.
- No recovery is called successful before a durable acknowledgement and fresh health evidence exist.
- The PRD and 360-task ledger remain synchronized with implementation and honest certification status.
