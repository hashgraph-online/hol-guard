# CIGAR artifact acquisition

Status: native source-build acquisition and exact package-tree reconstruction have real public artifact evidence on macOS arm64. This is one part of P4; it does not complete the user-facing updater or promote the bundled final 0.14.1 entry beyond `upstream_only`.

The release catalog owns the complete SDK/dependency filenames, hashes, byte lengths, package-tree digest and origins. The native worker handles transfer, cache verification and preparation. A version string or a successful download grants no activation authority. Native installation still requires a Guard-qualified platform/profile and actual interpreter, worker and feature checks.

## Declarative origins

`WheelSource` permits three forms:

| Kind | Meaning | Scope |
| --- | --- | --- |
| `github_cigar_release` | `tag` selects the exact wheel under `hashgraph-online/hol-cigar/releases/download/` | CIGAR SDK only; tag matches the SDK version |
| `pypi_file` | `path` identifies an exact content-addressed `/packages/aa/bb/<60 hex>/<locked filename>` file at `files.pythonhosted.org` | Dependency wheels only |
| `offline_bundle` | No network origin | Explicit operator import of the exact locked bytes |

No index lookup, latest-version resolution, alternate mirror, URL credentials, package build or downloadable adapter is accepted. SDK requests may redirect only to the exact source URL or `release-assets.githubusercontent.com`. Dependency URLs must remain exact. The origin check runs before DNS for every redirected hop.

Catalog revision 3 added the published protobuf file origin; revision 4 additionally carries the actual SDK/dependency Python requirement headers as described in [Interpreter compatibility](CIGAR_PYTHON_COMPATIBILITY.md). SDK/core/source/manifest/worker/tree/dependency hashes are unchanged. Qualification and features remain unchanged. Compatible future entries use the same source variants without changing application code.

Maintainers can supply repeated `--dependency-url FILENAME=URL` arguments to `scripts/cigar_catalog_entry.py` alongside the exact dependency wheels. The tool checks the narrow host/path/filename contract and retains the actual wheel hash, byte length and dependency closure. Missing origins remain explicit offline imports. The draft is still unqualified and cannot publish a catalog or establish manifest provenance.

## Transfer and cache

Acquisition reuses Guard's restricted downloader: HTTPS only, public-address DNS filtering, pinned TCP peer verification before TLS, hostname/certificate checks, bounded response headers and a single absolute transfer deadline. The CIGAR path adds an optional cancellation signal without changing the default transport contract. HTTP headers, body and TLS traffic share cancellation-aware socket I/O.

An install job has a 120-second overall deadline, at most three redirects per file and an exact catalog byte cap per wheel. A pending DNS resolution or TCP connect is bounded to at most five seconds; transfer I/O checks cancellation in 100 ms socket slices. Completed downloads are re-read through stable protected-file checks and hashed again before private cache publication. No timing guarantee is inferred for arbitrary blocked filesystem operations from the network cancellation test.

Only the bounded, content-addressed cache can supply preparation inputs. Cached files are rechecked against the exact lock, including offline retries. Download staging belongs to the durable job and carries its ownership marker; successful acquisition removes its temporary root, while cancellation/failure/recovery use the same bounded ownership-checked cleanup as bundle staging. A matching cache hash is never permission to select or enable a runtime.

Signed CDN query strings remain in temporary in-memory transfer state. Jobs, installation records, diagnostics and evidence do not save them. The client supplies build/interpreter/job IDs, never URLs, paths, trust roots or readiness facts.

## Managed networks

Native machine policy is loaded without updating its cache or reading proxy credentials. Public-registry refusal applies to dependency transfers and is checked again before publication. Invalid or inaccessible managed authority refuses acquisition.

This qualified mode uses direct pinned TLS with the transport's public WebPKI roots. A configured OS/managed HTTP proxy or custom managed trust bundle returns an explicit offline-import recovery code. It is not silently bypassed, and the custom CA alone never replaces additive public/platform trust. Supporting those network modes requires a separately tested transport path; exact offline wheel import already uses the same byte/tree verifier.

## Installation identity

Physical slot derivation v2 includes the exact build and shipped profile binding, immutable SDK/dependency lock facts, worker/tree digests and verified Python executable fingerprint. It excludes download origins, qualification status, feature order/list, qualification receipt and catalog checkpoint. Rehosting or approving the same bytes therefore does not derive another slot.

Existing persisted installation paths are not rewritten by this change. Archived owner-authenticated records still resolve and start through their own protected selection. Coverage for reuse across earlier internal slot derivations and explicit receipt refresh for newly qualified features remains follow-on work; changing qualification metadata cannot itself enable a feature or rewrite an active record.

## Recorded evidence

[The native acquisition receipt](evidence/upgrades-native-acquisition-20261026.json) binds the executing test image and 55 source fingerprints to [the raw test log](evidence/upgrades-native-acquisition-20261026.log). The recorded run passes all 32 registry/job/acquisition tests with zero failed or ignored.

The public acquisition test downloads the exact final 0.14.1 SDK wheel and protobuf 7.36.2 wheel into a disposable private profile, reconstructs 124 files / 11,454,530 bytes, and verifies tree `5ebfc715f581c40c9fce73209271479a1926d5044543a46c720ba0049c35e1f4`. It takes 2,557 ms in this run, reuses the verified cache on retry and starts zero SDK processes. Source-build installation and active install-only continuity tests also pass against the same exact locks, using separate disposable profiles and test-only catalog qualification. They do not demonstrate a shipped/frozen end-to-end download-and-switch workflow.

The shared transport suite passes 19 tests, including real TLS cancellation while headers/body are delayed, certificate/hostname refusal, peer pinning, DNS admission, size limits and deadline behavior. Cancellation returns within one second in the local delayed-response test; that is test evidence, not a general network latency promise.

Release/installer tests pass on Rust 1.99 and the Rust 1.88 minimum: 33 release tests and 13 installer tests. Their production Clippy check passes with warnings denied. Maintainer tooling passes 20 tests and Ruff. Full production native typechecking passes; the previously recorded broad Clippy baseline remains unresolved outside this change.

Official artifact references: [GitHub final release metadata](https://api.github.com/repos/hashgraph-online/hol-cigar/releases/tags/v0.14.1), [protobuf 7.36.2 metadata](https://pypi.org/pypi/protobuf/7.36.2/json). Transport API details were checked against the pinned ureq 3.3.0 source and [versioned documentation](https://docs.rs/ureq/3.3.0/ureq/).
