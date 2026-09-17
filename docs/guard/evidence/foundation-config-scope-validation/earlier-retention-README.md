# Foundation scoped configuration validation

These are exact retained receipts from the core held-capture backport (`dae0115961d43cfdb7e97a9807b253f01fa7baf9`) and initial daemon propagation (`1cb1068056c8eeef5babc5f4f355481b37bc06e0`). The manifest records SHA-256 and byte size for every original log and receipt. The suites overlap; their counts are not additive.

The core checks passed 92 tests with two skips and reported zero type errors (208 warnings). The initial propagation check passed 58 tests and failed two existing emergency-safe path cases. Both failures are retained unchanged: the RAM fixture was beneath `/dev/shm`, which the unchanged policy correctly rejects as an ordinary workspace. Only those two tests were repeated with ordinary `/tmp` fixtures; both passed. The original floor source digest, command, and cause are retained with that repeat. The six-file propagation type check reported zero errors and 363 warnings.

At those commits, four downstream reader keywords awaited the CLI and persisted-API backports. The original receipts preserve that incomplete scope. Later completion and combined checks have separate evidence. Foundation does not contain the implementation-only native Codex continuation authority or policy-input caches; these backports do not add them. No hosted analysis or security-alert resolution is claimed by these source checks.
