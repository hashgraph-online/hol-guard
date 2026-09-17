# Foundation daemon configuration scope validation

These are local source validation receipts for the foundation semantic backport. They do not establish fresh hosted CodeQL results, installed-host qualification, or a security-alert disposition.

The `core` and `propagation` directories retain the original receipt and log bytes. `historical-manifest.json` hashes each retained file; the source hashes in the commit receipts were checked against the exact historical commits. Counts overlap and must not be added.

The core attempt passed 92 tests with two platform skips. The initial propagation attempt passed 58 tests and failed two existing ordinary-workspace path tests because its `/dev/shm` fixtures fall inside the unchanged policy's forbidden `/dev` root. The original failures remain in `propagation/tests.log`. A separate, narrowly selected check with ordinary `/tmp` fixtures passed both tests without changing policy, source tests, or thresholds.

The historical propagation receipt records four deliberately deferred API keywords. Later foundation commits carry those dependencies through the existing CLI, persisted approvals, local approval completion, remote approval, command queue, and child process APIs. The daemon stores one stable reader object so an existing queue worker cannot silently receive a different scope. Foundation keeps its existing uncached policy compiler and approval architecture; implementation-only native Codex continuation authority was not imported.

The callback implementations and shared TOML parser are explicit synchronous-posture roots in the decision-critical I/O inventory. This describes their real synchronous metadata and decode work; it makes no zero-Python-I/O claim.

`final-validation.json` describes the composed foundation checks and hashes every retained final receipt. Large logs and source manifests are stored as gzip; decompression recovers the exact original bytes.

The combined focused run passed 318 tests, skipped two platform cases, and failed one existing two-second isolated continuation test with `continuation_adapter_timeout`. That original failure and bounded stored-state diagnostic remain retained. All 28 ownership tests, the authority and semantic gates, and full production typing (1,231 files; zero errors, 19,759 warnings) passed. Every check's 2,646-file source snapshot stayed unchanged.

A subsequent source review identified a remote package-audit home read outside the propagated callback. The narrow follow-up forwards the optional reader through that existing helper. Its five remote-reader cases and one unchanged reproduction of the original continuation test passed (six total); the changed production file also passed typing. The initial timeout cause remains unresolved and is not attributed to contention or dismissed. The two changed paths and exact final source commit are recorded in the final manifest. No test budget, policy floor, or production authority was relaxed.
