# Rust core performance tranche

This tranche implements the repeated-work portion of the HOL Guard Rust
performance PRD against source baseline
`2e672d2d950c6ec471005ddba46e49bba16dc23b`. It does not establish an installed
latency, throughput, memory, or platform qualification result.

## Production changes

The authenticated resident returns a typed lifecycle disposition together with
its response bytes. Only a successfully decoded and evaluated shutdown operation
requests shutdown. The transport no longer parses the entire payload again to
identify that operation. Framing, request digest checks, authentication, strict
JSON validation, error redaction, and panic containment remain in place.

Envelope validation retains its normalized harness, event, request ID, canonical
digest, and monotonic deadline in one owned value. Ordinary hook evaluation and
receipt creation use that identity. PreTool results stay typed through matrix
validation and receipt construction. PostTool evaluation transfers payload
ownership into its typed request and restores it before receipt construction;
it does not clone the payload tree. Approval reconstruction retains its separate
identity consistency check.

Authenticated snapshot admission builds canonical harness indexes once and
retains the original signed snapshot unchanged. The store publishes an
`Arc<AdmittedPolicySnapshot>` containing both. Evaluation performs indexed
lookups rather than validating every effective-policy entry and normalizing
every configured harness on every hook. Request-time expiry, current generation,
scope, authority checks and approval mutex fences remain active. Admission and
restart continue to reject conflicting aliases before publication.

The helper uses the same strict JSON visitor to project the root timeout field.
Nested duplicate keys, string limits, collection limits, invalid UTF-8, nesting
limits, and trailing data remain checked. The helper does not materialize the
nested payload as a second `Value` tree. This is an allocation reduction, not a
claim that untrusted bytes can skip validation or that the helper and resident
share one parse across their process boundary.

Helper metadata processing and lease acquisition consume the existing client
deadline. Resident payload reception, queueing and JSON decoding consume the
deadline supplied to the edge. The same absolute deadline reaches source reads,
output extraction and scanning; the scanner checks it again after classification.
The receipt retains the original declared budget. The client still supplies the
outer end-to-end timeout, and individual bounded filesystem/regex operations are
not preempted by this cooperative deadline.

Output extraction appends to bounded buffers and counts each complete fragment
once, instead of building vectors of copied strings and then joining and
recollecting the output. Newline ordering, character limits, truncation and
output digests are compared against an independent copy of the original
extractor. Scanner windows borrow the first chunk and retain their Unicode tail
as one suffix copy, with split-token and unrelated-document tests.

## Source-level operation accounting

These counts describe the ordinary native hook path. They are not allocator
measurements and do not describe every approval or compatibility route.

| Operation | Baseline | Candidate |
| --- | --- | --- |
| Helper timeout validation | One full strict payload tree | One strict traversal retaining timeout metadata |
| Resident strict payload parses | One evaluation parse plus one shutdown parse | One evaluation parse |
| Ordinary edge canonical request identity | Twice | Once |
| PreTool `Value` to typed-result conversions | Twice | None |
| PreTool result serialization for wire response | Once | Once |
| Effective-policy full-map validation during a hook | Once | At generation admission instead |
| Canonical harness-map scans during a hook | Full configured maps | Canonical index lookups |
| PostTool raw-payload clone into typed request | Once | None |

`validate_v3`, generation authentication, the envelope size check, canonical
digest calculation, and response/receipt size checks are retained. This tranche
does not substitute path or mtime caching for security identity validation.

## Reproducible diagnostics

From `rust/`, run:

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test -p hol-guard-runtime -p guard-hook-core -p guard-scanner --release --locked benchmark_ -- --ignored --nocapture --test-threads=1
```

Each diagnostic prints bounded JSON containing its fixture name, sample count
and baseline/candidate p95 in microseconds. Each arm has 100 observations in five
rounds of 20, with the first arm alternating by round. The estimator is the
nearest-rank 95th observation. Fixture construction and initialization are
outside timed sections. The output-extraction baseline is the original source
implementation; timeout projection compares the full strict visitor with its
projected mode. These diagnostics compare kernels, including their local
allocation and result destruction, and exclude transport and installed launchers.

The initial local release run on 2026-09-17 used Rust 1.88.0, Linux x86_64 and a
shared KVM host exposing nine Intel Xeon Platinum 8370C CPUs. Background activity
was not controlled. Results are exploratory, not a release gate:

| Kernel / synthetic fixture | Baseline p95, µs | Candidate p95, µs |
| --- | ---: | ---: |
| Output extraction, ASCII 16 KiB | 77.664 | 4.063 |
| Output extraction, Unicode 12 KiB | 43.067 | 3.106 |
| Output extraction, many parts | 26.652 | 4.079 |
| Output extraction, maximum characters | 34,143.848 | 10,988.614 |
| RegexSet prefilter, clean 17,758 bytes | 174.450 | 82.718 |
| RegexSet prefilter, clean 1,135,966 bytes | 11,845.513 | 4,275.175 |
| RegexSet prefilter, matching approximately 16 KiB | 141.654 | 51.098 |
| RegexSet prefilter, sample-heavy approximately 17 KiB | 258.926 | 291.797 |
| Timeout projection, 16 KiB string | 8.715 | 8.196 |
| Timeout projection, maximum 1 MiB string | 727.250 | 842.378 |

A timeout-only repeat after the first compile completed measured 4.239/3.950 µs
at 16 KiB and 434.542/290.007 µs at 1 MiB. Both runs are retained here because
the shared-host variance prevents treating either one as platform qualification.
The additional projection benefit is bounded memory materialization; it does
not remove the strict validation traversal.

The RegexSet alternative remains test-only. Its sample-heavy fixture regressed
in the initial experiment, so this tranche does not replace the production
classifier with a blanket prefilter. Per-match suppression and classifier
ordering are checked for both implementations. A later selection needs the
full workload distribution and installed-path evidence.

## Validation and outstanding evidence

The local Rust workspace passed 196 tests, with three diagnostic benchmarks
excluded from normal test runs and executed separately in release mode. This
includes command classification, rule contracts, source mutation, snapshot
admission/restart, approval/replay, scanner, receipt identity and strict JSON
suites. The workspace passed Clippy with all targets and warnings denied.
The existing authority and I/O ownership gates also passed. Those gates have
the scope of their existing analysis and are not latency evidence.

| TODO | State in this tranche |
| --- | --- |
| RSP-037 | Partial: source operation accounting and small/large kernel diagnostics; allocator attribution and installed spans remain. |
| RSP-038 | Implemented: typed lifecycle disposition with strict malformed-operation tests. |
| RSP-039 | Partial: timeout projection avoids the nested payload tree; complete strict validation remains in each trust boundary. |
| RSP-040 | Implemented for the ordinary edge: immutable validated identity, cross-language golden digest and approval regression coverage. |
| RSP-041 | Implemented: typed PreTool result through matrix validation and receipt creation. |
| RSP-042 | Implemented: effective-policy validation and canonical selector compilation at generation admission. |
| RSP-043 | Implemented: immutable shared snapshot/index ownership with restart and generation-swap tests. |
| RSP-044 | Implemented: bounded concatenation and payload ownership transfer, with independent extraction parity and local diagnostics. |
| RSP-045 | Experiment complete: RegexSet alternative retained only in tests after a sample-heavy regression. |
| RSP-046 | Implemented cooperative deadline propagation and chunk/Unicode/document isolation checks; installed timeout qualification remains. |
| RSP-047 | Local core suites passed; supported-platform and resident integration suites still require CI. |
| RSP-048 | Unqualified: requires native-client and installed-artifact comparisons, process-tree measurements and the PRD's sample/platform requirements. |

The local environment rejects socket creation, so authenticated resident and
installed-launcher integration could not run here. These changes must obtain
that evidence from the release CI environment. Passing the kernel experiments
does not authorize a claim of a 30% installed improvement or a platform SLO pass.
