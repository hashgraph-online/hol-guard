# One-use Rust SDK tap journal diagnostic

On 2026-10-21, code commit `596a10e2` added a Root-owned, exclusive
`<run-id>.sdk-tap.json` journal under the existing Rust staging worker lease.
It requires the exact keyed started marker before writing, caps the retained
set at 16 sessions, 1,000 events, 12 MiB observed frame bytes and 1 MiB
journal bytes, and requires both docs and mail families. It checks fixed
peer UID/GID profiles, ancestry metadata, event sequence/family/hash/byte
metadata and aggregate totals before canonical serialization. The new file
must be mode 0600, Root-owned and single-link; Rust fsyncs the file and
parent directory and rechecks the held and visible inode before returning a
SHA-256 receipt. A second write for the same run fails.

A Root-only ARM VM test reserved a fresh keyed synthetic job, wrote two
session records, reopened the private bytes against the receipt digest,
rejected replay and a wrong digest, then rejected changed file bytes. The
receipt and journal both state that child reports are unauthenticated,
the host has not retained a pin, and execution is ineligible. This writer
stores reported frame digests and metadata; it has no raw-frame pipe from an
isolated child and cannot independently prove SDK transport or product
effects. Its synthetic test does not constitute a live control.

The static no-debug ARM64 worker test binary was 11,536,056 bytes with
SHA-256 `c9299a32c36fc680a141e659a608a47d200fe95f87c8bd5ac31c550d464ab995`.
Host, guest inbox and Root-installed hashes matched; the installed copy was
mode 0500 with one link. The Root-only journal test passed explicitly, and
the default full worker library suite passed 85 tests with seven intentional
ignores. Warnings-denied ARM64 Clippy, Rustfmt and `git diff --check` passed.
After removing the guest inbox, VM free disk was 8,775,876,608 bytes, above
the 8-GiB floor.

The [execution checklist](gauntlet-rust-execution-checklist.md) still requires
an authenticated UID-10001 child, raw-frame validation by the Root parent,
terminal/host digest binding and fresh six-role SDK/Native reconciliation.
