# CIGAR interpreter compatibility

Status: native release-specific Python patch preflight and exact wheel metadata binding are implemented and tested. [Private interpreter preparation](CIGAR_PRIVATE_PYTHON_PREPARATION.md) now has exact native CPython 3.14.10/source-build SDK evidence. Durable setup/discovery, authenticated registration/runtime binding and broader conditional dependency/ABI coverage remain part of P4. The bundled final SDK remains upstream-only; these checks do not promote or enable it.

The shipped adapter still requires a measured final CPython 3.14 interpreter with the supported platform ABI, standard GIL and release build. A compatible later 3.14 patch is selected through measured interpreter facts and catalog data, without changing a Python version constant in application code.

## Exact requirements

Each SDK/dependency `WheelLock` can include `requires_python`, taken from its actual `Requires-Python` metadata header. Catalog validation bounds the string and parses it as a Python version-specifier set. A malformed constraint refuses catalog resolution.

The current exact final 0.14.1 wheel header is `<3.15,>=3.14`; protobuf 7.36.2 declares `>=3.10`. Both accept the tested final CPython 3.14.7. A hypothetical future dependency with `>=3.14.8,<3.15,!=3.14.9` rejects 3.14.7 and 3.14.9 while accepting eligible 3.14.8 and 3.14.10. Those are synthetic compatibility tests, not qualification of real future SDK/interpreter bytes.

The requirement check runs in three places:

1. Native installation resolves the trusted release against the registered measured interpreter before creating a job or starting any download.
2. The worker checks its captured release/interpreter again before preparation.
3. Runtime startup checks the interpreter's actual isolated probe result before importing/starting the SDK. An altered registration record cannot substitute for that observation.

Insufficient patch compatibility returns `cigar_python_version_required` through the native job preflight, with the usual `native_context_assistance_` prefix. Actual startup reports `python_release_incompatible`. Release metadata exposes the precise constraints for the forthcoming operator/UI recovery flow. Passing a version check alone is never proof of an executable, package, SDK readiness or execution authority.

The native wheel reader also requires a declared constraint to match the actual bounded `METADATA` header exactly and exactly once. Missing, duplicate or conflicting headers refuse preparation. This catches catalog errors before an SDK process starts. The maintainer draft tool extracts the original header, checks it against its explicit target final Python version, and records it with the exact wheel hash/length.

## Existing installations

`requires_python` is optional with a deserialization default and is omitted from serialized locks when absent. Authenticated historical receipt payloads that predate the field still verify and resolve without being rewritten. The adapter's existing CPython 3.14/final/ABI/build checks continue to govern them; absence is not permission to run another Python family.

The physical slot still binds exact artifact bytes rather than the spelling of added catalog annotations. SDK/dependency hashes bind their real metadata; the new field does not change the installation path or select/enable a runtime. Archived receipts, future qualification refresh and alternate historical slot reuse remain distinct concerns; no active receipt is silently rewritten here.

## Evidence and limits

[The saved native receipt](evidence/receipts.json) binds 62 source fingerprints, the executing image and the complete successful log recorded by SHA-256 in [receipts.json](evidence/receipts.json). All 33 native registry/job/acquisition tests pass with zero failed/ignored. They include refusal of a synthetic later-patch requirement before any job/download/SDK, exact public acquisition/tree reconstruction, real managed installation on CPython 3.14.7 and active install-only continuity through cancellation. The unchanged exact public SDK/dependency hashes are recorded in the receipt.

The maintainer tool was also run against the actual final SDK wheel, dependency wheel and independently recorded release manifest. Its entire generated build entry equals the bundled catalog entry, including both original Python headers, while remaining unqualified.

Release tests pass 36/36 and installer tests 14/14 on Rust 1.99 and Rust 1.88. Context-assistance default tests pass 44 with eleven existing actual-SDK cases left explicit opt-in; the real managed-install/continuity scenarios are included in the separately recorded native run. Maintainer tests pass 20/20 and Ruff. Production native typechecking and production release/installer Clippy with warnings denied pass. No SDK worker/broker remained after the tests.

An earlier development run recorded the semantically equivalent SDK range in the wrong literal order and correctly failed three actual-artifact cases before publication. The catalog was corrected from the measured header, its complete build was compared with the generated real-wheel draft, and all 33 cases passed on rerun. That failure log's SHA-256 is recorded in [receipts.json](evidence/receipts.json). Verification was not relaxed to hide it.

This proves source-build Python requirement handling for the exact claimed artifact/platform. It does not complete private Python provisioning, every conditional dependency/wheel ABI case, switching/rollback, installed/frozen acceptance or another platform's qualification. An unsupported Python family or SDK/worker/storage contract still needs a reviewed shipped adapter/Guard update.
