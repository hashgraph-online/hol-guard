# CI gate ownership

The required `CI` workflow validates the complete locked Linux Rust workspace once.
`native-workspace` runs Clippy (with warnings denied) and all workspace test targets
in parallel matrix jobs. The existing five-minute `native-command-evaluators` job
still checks formatting, builds the release compiler/runtime and supplies matching
artifacts to Python tests. Rust lint/tests do not delay that artifact producer or
its 128-shard Python fan-out. The required `ci (3.12)` aggregate directly requires
the complete Rust matrix as well as Python checks; failed, cancelled or skipped
Rust validation cannot turn the aggregate green. No test failures are ignored.

Specialized native workflows retain their own release builds, source-bound
projections, security/authority probes, differential tests, transport tests, and
installed-artifact checks. Only main-targeted PRs and pushes to main skip duplicate
Linux workspace validation. Releases, stacked PRs, other push branches and manual
dispatch retain standalone checks. The existing daemon-hardening schedule also
retains them; this change does not add schedules to workflows without one.
Windows and macOS workspace validation remains on those platforms. The full Rust
suite is retained, not replaced by Python legacy tests.

The fifteen-minute limit on each parallel Rust job is a cold-cache failure bound,
not a latency target. It no longer combines lint, tests, release compilation and
Python preparation in one serial job. Warm-cache job times and full PR elapsed
time must be measured separately; reducing duplicate work is not proof that every
PR completes in under five minutes.

A PR's extension binding comparison uses the first parent of the exact merge
checkout being tested. `scripts/ci/pr_merge_base.py` verifies both the event merge
SHA and its contributor-head parent before returning that baseline. This avoids
attributing newer `main` changes to an older contribution. An unexpected checkout
fails closed instead of silently choosing a different baseline.

All portable fixtures still pass through native evaluation without executing their
target commands. Actual PR source/fixture bindings, trust defaults, generated
projection verification, and installed-wheel checks remain enforced. CI does not
rewrite fixture expectations or require contributors to rebase just for generated
catalogs. `builder-evidence/checkout.txt` preserves tested provenance even when
preparation fails, instead of a missing artifact obscuring the first error.

Repository security scanners and review requirements are unchanged. A product
behavior failure is fixed in the implementation or its contradictory fixture; it
is not waived by reducing duplicate CI work.
