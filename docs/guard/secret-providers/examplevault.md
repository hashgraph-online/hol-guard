# Example Vault provider adapter

This is the synthetic conformance provider for the reviewed Vault KV v2 adapter core. The host, publisher,
reference and fixture value are test-only identifiers. The adapter uses Guard's exact-host HTTPS transport,
bounded JSON parsing and an external provider enablement gate.

The provider is disabled by default. Local enablement is required before a connection or value delivery can
run. Connection credentials are held in the native secure store under the provider connection scope. Guard
exports metadata and digests only. Secret values and provider credentials do not enter receipts, telemetry,
agent text or provider contribution artifacts.
