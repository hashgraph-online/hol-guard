# Local risk report privacy threat model

This document defines the security boundary for `hol-guard risk-report`.

## Assets that must stay local

The report generator must never serialize raw prompts, commands, source code, findings, file paths, workspace names, hostnames, usernames, secrets, tokens, raw receipts, or customer/account identifiers.

The command reads the existing local Guard status model and emits only coarse posture fields documented in `local-risk-report.md`.

## Threats and mitigations

### Sensitive-content leakage

Risk: a status payload contains local paths or other sensitive fields and they accidentally flow into the report.

Mitigation: the report is built by allowlisting coarse fields and recomputing summaries. Unknown status keys are ignored. Tests inject sensitive values and assert they do not appear in JSON or HTML.

### Report tampering

Risk: a shared report is edited after generation.

Mitigation: every sanitized report includes a SHA-256 digest over its canonical report fields. Verification fails when a covered field changes. This is an integrity check, not identity attestation or a cryptographic signature.

### False assurance

Risk: a report is treated as proof that a machine is secure or that every attack is blocked.

Mitigation: the schema and HTML explicitly state `certification=false` and include the adjacent limitation that coverage depends on Guard version, harness, event surface, policy, and runtime state.

### Accidental publication

Risk: generating a report uploads it or makes it crawlable.

Mitigation: the CLI only writes to stdout or a user-selected local file. The HTML contains `noindex,nofollow`. There is no network call in the report generator. Any later upload/publication is a separate, explicit user action.

### Local path disclosure through output location

Risk: the command output message could expose a chosen absolute destination path to a log collector.

Mitigation: operators should treat the terminal itself as local. The report body never contains the output path. Automated callers that need stronger log hygiene should consume stdout rather than `--output`.

### Resource abuse

Risk: a maliciously large nested status payload causes excessive report work.

Mitigation: the generator reads only a bounded set of scalar counters and harness summary entries already produced by the trusted local Guard status model. It does not recurse through unknown payload fields or read referenced files.

## Trust boundary

A local report proves only that its sanitized fields have not changed since the digest was calculated. It does not prove who generated the report, that the host was uncompromised, or that every Guard protection layer was active beyond the status represented in those fields.
