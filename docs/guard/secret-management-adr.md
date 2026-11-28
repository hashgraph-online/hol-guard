# ADR: Guard secret custody and delivery boundaries

Status: accepted for the v1 implementation

## Decision

Guard treats a secret reference as metadata. The native resident owns parsing, canonicalization, provider
selection, secure-store access, approval binding, delivery and output redaction. A secret value may exist in
resident memory or in the selected child process only. It is never returned in a broker response, review card,
Python object, dashboard response, receipt, telemetry event, URL, command argument or ordinary workspace file.

The first-party store uses a service namespace separate from approval enrollment and the internal encrypted file
store. macOS uses Keychain generic-password items, Linux uses Secret Service attributes, and Windows uses a
per-user generic credential. Unsupported or headless platforms return an unavailable result and do not fall back
to plaintext or the internal file store.

External providers use a closed manifest and a reviewed typed adapter. `default_enabled` is always false for an
external provider. A local administrator must enable it. Provider responses and sponsor metadata are evidence only
and can tighten a local decision, never create an allow or weaken a Guard floor. Provider calls remain off the
ordinary hook path.

Version 1 supports environment and stdin delivery. The file-descriptor contract is represented in the closed
schema and binding model, but the executor returns `secret_sink_unsupported` until a platform-specific inherited
handle implementation is qualified. Direct agent text, arguments, URLs, query strings, clipboard, shell history,
workspace files, receipts and telemetry are rejected.

## Approval binding

A materialization binding includes provider identity, connection identity, canonical reference digest, version
selector and resolved version when known, capability, sink, destination, process digest, workspace digest,
purpose, policy digest and extension digest. It excludes the secret value. Any changed field requires a new
review. A supported review must retain both Allow once and Always allow under the repository approval invariant.
A missing executable binding returns an unavailable or approval-required result and never presents an approval that
cannot run.

## Compatibility

Existing raw environment and sensitive-file reads remain reviewable floors. A `guard-secret://` reference never
quietly changes the classification of a raw `env`, `printenv`, `process.env`, `os.environ` or credential-file
read. Existing approval enrollment and encrypted-file state retain their current namespaces and semantics.
