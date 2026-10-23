# Python/Rust VM bridge RPC contract parity

The Rust evidence library now validates the Python bridge's fixed RPC body
above its existing HMAC frame codec. It requires one canonical UUID, an
ASCII operation name of at most 32 bytes, an object payload, and exact
request fields. A response must bind the same request ID and operation;
success carries an object result, while only the two fixed remote error
codes and their exact fields are accepted. Remote operation failures remain
distinct from protocol errors, which require the live codec to be poisoned.
The operation name is a fixed registry key; trusted callbacks must validate
any path or other parameter in the payload.

The checked-in fixture generator invoked the branch's Python
`vm_bridge_rpc.py` at source SHA-256
`ae15ffd28a9e5e83a117ec5c558f29c4ee98b4fd6448a45c00219da976ee76e9`.
It froze 15 request and 15 response cases, including wrong IDs, extra or
missing fields, invalid names and UUIDs, malformed errors, and valid remote
failures. The Rust test also hashes the source file so a changed Python RPC
contract cannot silently reuse the old fixture. The 30 decisions and exact
protocol-error reason classes matched on macOS and in an offline Linux
ARM64 container. The complete macOS evidence crate test run and local
Clippy passed. The prior HMAC frame parity suite still
covers MAC bytes, direction, sequence, replay and budget poisoning.

This is a data-only parser. It does not own a management FD, dispatch a
trusted operation, implement cancellation or terminal markers, authenticate
the OMP/Bun process, or establish model inference or benchmark eligibility.
