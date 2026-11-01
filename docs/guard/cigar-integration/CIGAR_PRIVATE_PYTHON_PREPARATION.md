# Private CIGAR interpreter preparation

Status: exact native preparation, relocation, complete-tree verification and stopped SDK qualification have real CPython 3.14.10/macOS arm64 source-build evidence. Durable setup jobs, automatic acquisition, authenticated registration and runtime binding remain incomplete. This is a preparation layer, not a delivered end-user Python installer. The bundled darwin-arm64 interpreter and SDK entries were promoted to `guard_qualified` from real runs of the maintainer qualification examples (see [the maintenance runbook](CIGAR_RELEASE_MAINTENANCE.md#current-darwin-arm64-qualification)); the rest of this document describes the preparation layer those runs exercise.

## Catalog and build identity

The existing authenticated catalog now has an optional `interpreters` array. Old documents and archived SDK receipts omit it safely. `InterpreterBuild` records the final CPython patch, platform, upstream release/source commit, compressed archive digest/length, materialized tree digest/count/length, executable digest, qualification and withdrawal. Preparation and qualified setup resolve through distinct typed methods; preparing trusted bytes grants no activation or automatic setup capability.

The fixed origin is `astral-sh/python-build-standalone` on GitHub. Asset filenames are composed from the version, release date and shipped platform mapping for the standard-GIL `install_only_stripped.tar.gz` layout. Catalog data cannot supply an arbitrary host, URL, installer script or adapter. Physical Python slot identity binds immutable build/source/artifact/tree/executable facts while excluding qualification and catalog checkpoint changes.

The native releases response includes `interpreter_builds` as metadata. It does not probe Python, prepare files, register a selection or change enabled preferences. Existing registered CPython 3.14.7 remains eligible; listing a later build does not select it.

## Preparation and verification

`guard-cigar-install::prepare_python` accepts a trusted resolved build and a native/operator-owned artifact path. It verifies the complete compressed digest/length before bounded gzip/tar parsing. The supported layout has the `python/` prefix and ordinary GNU/USTAR files, directories and internal file aliases. PAX/sparse/extension/special records, unsafe paths, aliases outside the tree, dangling/cyclic/directory aliases, duplicate/case collisions, extra compressed members and nonzero trailing tar data refuse.

Safe internal aliases become independent protected regular files. The prepared interpreter therefore has no symlink dependency outside the exact materialized tree. UID/GID from the archive are not applied; set-ID modes refuse. Preparation computes the complete expected tree, counts, expanded bytes and executable digest before writing anything. The shared writer requires a fresh canonical private directory and creates files exclusively, with owner-only read/execute intent and cancellation checks.

Bounds are 128 MiB compressed input/per-file, 256 MiB decoded tar, 256 MiB materialized files, 8,192 archive members, 24 path components and the existing preparation control's 120-second maximum. These are separate storage/allocation bounds, not a claim that peak process memory is only 256 MiB. Unsupported layouts require a reviewed preparer change; they are not silently extracted with a general installer.

`verify_python_tree` returns a non-deserializable verified bundle only after checking the canonical private root, complete file inventory, permitted protected modes, stable single-link file reads, expected counts/bytes/digest and final nonsymlink executable digest/mode. Unknown empty directories also refuse. Root identity is checked across the traversal. This operation is explicit setup/startup work, not passive status work. It does not prove an interpreter process or SDK readiness by itself.

## Maintainer workflow

`scripts/cigar_interpreter_entry.py` takes an approved archive, independently verified GitHub release metadata, platform and a new output path. It verifies asset name/origin/digest/length, extracts the source commit, checks the supported layout and computes exactly the native materialized-tree identity. It supports an explicit verified source revision when the release's target is a branch name. Optional build-ID input allows a separately identified rebuild. The tool runs no interpreter/SDK, installs nothing and emits only an upstream-only draft with no qualification receipt.

The actual generated entry equals the bundled CPython 3.14.10 entry. Synthetic 3.14.11 tests demonstrate later-patch data generation; they do not claim actual future bytes. A future compatible SDK can continue using an existing eligible interpreter. Installing the newest Python merely because it is listed is not part of the update policy.

The native `qualify_python` maintainer example takes `PYTHON_BUILD_ID SDK_BUILD_ID FRESH_PRIVATE_HOME PYTHON_ARCHIVE SDK_WHEEL DEPENDENCY_WHEEL [...]`. It prepares both exact trees, moves Python from staging before probing, validates actual final CPython/platform/ABI/build facts, runs all four SDK feature checks on synthetic data, closes the SDK and verifies the full interpreter tree again. It saves a stopped receipt and never registers, selects, enables or promotes qualification.

The preparer and SDK session have separate cancellation scopes. SDK close permanently revokes the session signal. Final file verification uses the still-valid preparer scope rather than clearing an old SDK signal. The example retains the total preparation deadline and bounded SDK operations; the future job owner must propagate its cancellation/deadline down to session scopes.

## Real evidence

[The saved receipt](evidence/receipts.json) binds 71 current source fingerprints to both executing images, artifact identities and logs. Both logs are recorded by SHA-256 in [receipts.json](evidence/receipts.json).

| Identity | Exact value |
| --- | --- |
| Python build | `cpython-3_14_10-20261026-darwin-arm64` |
| Source revision | `fa506e0858ac9f2cc5b289c137b888a2aa24d1ee` |
| Archive SHA-256 | `95eb8c87d16af37c54e9765e31d8c56c0d8ffa9968ea0f704f73a9b83f84e9f9` |
| Materialized tree SHA-256 | `1e446c992cf2c8b93f33925a422e5f7f5f7af770536589ec4c065a567bb88375` |
| Executable SHA-256 | `26b5194d2beb09e648b4676ddc18a1384f182a7ed84f3db73106096aba6febf4` |

The 26,753,457-byte archive becomes 1,701 files / 106,491,517 bytes, including materialized aliases. The actual isolated probe reports final CPython 3.14.10, `cpython-314-darwin`, release build and standard GIL. Exact final CIGAR 0.14.1 passes graph, sharing, SQLite persistence and execution handoff; the runtime closes and Python's full tree stays unchanged. The recorded end-to-end preparation/qualification takes 64,705 ms here, not a general performance guarantee. No system Python or running Guard profile changes.

The existing CPython 3.14.7 path also passes all 33 native registry/job/acquisition tests, including inactive/idempotent installation, uncertain-publication reconciliation, public wheel acquisition and active preparation/cancellation continuity with unchanged generation/preferences. That current-runtime fixture uses final 0.14.1, not original b47380. No real newer CIGAR release is claimed; the later real build here is the interpreter.

Release/installer suites pass 38/19 tests on Rust 1.99 and Rust 1.88. Maintainer tools pass 33 tests (20 SDK, 13 interpreter) plus Ruff. Production release/installer Clippy passes with warnings denied; full native production typechecking passes. The earlier broad Clippy baseline remains separate. No SDK worker/broker remains after actual qualification. The 500-line source guide and original 82/84 byte-preservation audit remain satisfied.

Sources: [official distribution documentation](https://raw.githubusercontent.com/astral-sh/python-build-standalone/main/docs/distributions.rst), [official release API used for the captured metadata](https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest), and [the exact downloaded archive](https://github.com/astral-sh/python-build-standalone/releases/download/20261026/cpython-3.14.10%2B20261026-aarch64-apple-darwin-install_only_stripped.tar.gz). The initial page extraction was inconsistent; actual official API bytes and the downloaded digest/length were checked directly before native execution.

## Next integration boundary

Do not turn this into managed setup by calling the existing external-interpreter registration route. Add an owner-authenticated managed-interpreter receipt and archive fallback/withdrawal checks. Bind SDK installations to the full private Python build/tree, preserving existing v1/v2 records and historical slot reuse; executable SHA alone can alias different library trees or paths.

Wire exact acquisition through the native pinned transport and managed network policy, with cache/offline support, shared preparation lease, durable jobs, cancellation, ownership-marked staging, publication and recovery. Prefer an existing eligible verified interpreter; bootstrap only under explicit preparation policy. Keep current actors and disabled preferences unchanged. Add actual setup/cancellation/recovery and packaged/frozen acceptance before promoting either catalog entry. Broader conditional dependency/ABI and preview/core/tag compatibility coverage remains part of the full P4/P7/P9 work, followed by P5/P6 data/cutover and P8/P10 UI/packaging/performance acceptance.
