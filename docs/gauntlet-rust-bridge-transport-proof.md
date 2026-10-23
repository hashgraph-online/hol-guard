# Authenticated Rust management transport and RPC proof

Code pin `a7ad23d7` adds `gauntlet-agent-bridge` above the existing
Python-compatible HMAC frame codec and strict RPC body parser. The pinned
Python inputs are `vm_bridge_io.py` at SHA-256
`014181b2a9a1e377b94b72b543016d5df41e21a2b2bc91297b5846965712bc0b`,
`vm_bridge_rpc.py` at
`ae15ffd28a9e5e83a117ec5c558f29c4ee98b4fd6448a45c00219da976ee76e9`,
and `vm_bridge_frames.py` at
`f2d731788c2c82f4882a37ca4c9336b55aef80cd5d27a5e051af42a60c68460e`.

The Rust channel owns distinct management descriptors and accepts only a FIFO
or an AF_UNIX stream socket. It sets nonblocking and close-on-exec flags,
uses a monotonic deadline and cancellation flag during bounded poll/read/write
loops, refuses an announced frame length before allocating the body, and
invalidates the codec after any transport or protocol failure. A failed write
cannot reuse its reserved HMAC sequence. Its client generates a fresh v4
request ID and admits one request at a time under a deadline-bound lock.
Responses bind the exact request ID and operation. Its server accepts a fixed
registry of at most 32 trusted callbacks; an unknown operation invokes none.
Only bounded object results and the two fixed remote error codes pass.

Seven real-descriptor transport tests and four RPC tests passed on macOS and
in an offline Linux ARM64 Rust 1.88 container. The tests cover Python-frozen
HMAC wire bytes, bidirectional pipes, oversize and truncated frames, EOF,
deadline, cancellation, bad descriptors, failed writes, wrong direction,
single-flight timeout, registry validation, remote failure and response
binding. Two additional macOS tests exchanged actual requests and replies
with the pinned Python `BridgeIO`, `BridgeClient` and `serve_one` over Unix
sockets in both directions. Workspace Rustfmt and warnings-denied local Clippy
passed. The offline ARM64 container lacked Python, so its two Python-process
interop tests skipped; the isolated macOS and Linux ARM64 CI jobs now invoke
the crate with Python available.

This is an owned transport and fixed operation dispatch, not a live benchmark
producer. The caller must independently authenticate the management channel,
deliver a fresh private key, pin the trusted operation implementations, and
bind OMP/Bun, SDK, provider and terminal identities. It does not execute a
model, publish a result or change the passive PR gate.
