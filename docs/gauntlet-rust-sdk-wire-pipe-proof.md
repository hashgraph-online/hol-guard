# Bounded SDK raw-frame pipe diagnostic

On 2026-10-21, code commit `d3e6a879` added a bounded binary handoff for
raw SDK MCP frames. The relay reports each frame only after byte-identical
forwarding. A separate reader reparses the reported bytes with strict
duplicate-key rejection, request/response matching and independent wire and
canonical JSON SHA-256 digests. The canonical digest can later be compared to
the Native controller audit; it is distinct from the raw wire digest when the
SDK uses different JSON whitespace. The protocol requires a zero terminal,
EOF, a complete request/response ledger, at most 1,000 frames, 1 MiB per
frame and 12 MiB total. A malformed, truncated, orphaned or unfinished
exchange refuses.

The Linux ARM64 VM tests included an actual Unix-stream relay feeding a
separate raw-frame pipe reader, plus valid and refused protocol fixtures. The
three targeted pipe tests passed; the complete worker library suite passed
89 tests with seven intentional ignores and no failures. Warnings-denied
ARM64 Clippy, Rustfmt and `git diff --check` passed. The no-debug ARM64 test
binary was 11,627,592 bytes with SHA-256
`c979f9de0dbaf0c03c390c2bb8ca05a2aff8a65922b4046e94e89bb29d200f55`.
Host, guest inbox and Root-installed copies matched that digest; the Root
copy was mode 0500 with one link. The guest inbox was removed afterward.

The pipe still uses an in-process test harness. No UID-10001 child is
launched or independently authenticated, and a child could omit or forge a
report. The parent caller must impose a read deadline and reap the child;
the generic reader alone cannot enforce either. No live candidate was tapped,
no journal or terminal contains these raw frames, and this proof does not
establish Guard causality or execution eligibility. The
[execution checklist](gauntlet-rust-execution-checklist.md) retains those
exits as open.
