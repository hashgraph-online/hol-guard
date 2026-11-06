# appimg: Guard contribution kit

This is generated contributor knowledge, not a security certificate. The extension
is External, opt-in, and off until an administrator enables it. Generation and
validation never run the target or change Guard policy.

## Review first

Read `report.json` and inspect every operation against the upstream implementation.
Copy the review file from this kit's parent directory:

```sh
cp KIT/review.json REVIEW.json
```

Edit `REVIEW.json`. Changed behavior needs
`reviewed: true`, rationale, and an HTTPS evidence reference. Names, descriptions,
help flags, and MCP annotations do not establish safety. Unknown CLI invocations
retain review; unknown MCP tools inherit existing Guard handling.

Recompile edits into a new directory from this kit's parent directory:

```sh
hol-guard extensions generate --from snapshot --input KIT/discovery.json --review REVIEW.json --output REVIEWED_KIT
hol-guard extensions validate REVIEWED_KIT
hol-guard extensions apply REVIEWED_KIT --repo /path/to/hol-guard
```

Replace `KIT`, `REVIEW.json`, `REVIEWED_KIT`, and the checkout path with your actual paths.
Edit the copied review file before running snapshot generation. Inspect the plan,
then apply with `--expected-plan PLAN_DIGEST --write` using its printed digest.
Apply never commits, activates, or submits a PR.
Existing manual edits are conflicts, not permission to overwrite work.

## Native verification in the destination checkout

Stage the shared review resources before running contribution tests:

```sh
python scripts/release/stage_guard_cloud_review_artifacts.py
```

The command source is `contributions/command-sources/command.appimg.json` and its portable fixture
is `tests/fixtures/command-source-appimg.v1.json`. Kit validation compiles the source and
runs these cases with Rust. CLI kits do not generate a Python detector or a
Python test module.

After integration, follow the [native validation sequence](https://github.com/hashgraph-online/hol-guard/blob/main/docs/guard/extension-builder/VALIDATION.md):
regenerate the complete program, rebuild the native compiler and runtime, and
run the fixture with a build envelope assembled from the destination checkout's
canonical sources. The kit's `base: "packaged"` envelope is for a new addition;
it cannot replace an extension already embedded in the rebuilt compiler.

Run the shared contribution checks:

```sh
python -m pytest tests/test_guard_extension_contribution.py tests/test_guard_mcp_server_contribution.py
```

The generated cases exercise Guard's native parser and registry, not the target's
behavior. Add implementation-specific cases before submitting a contribution.
Never run destructive commands merely to satisfy a test. Review the full Git diff,
including publisher metadata, review rationales, and URLs, before making it public.

## Drift and boundaries

The snapshot records a claimed upstream version, not binary or server attestation.
Changed discovery invalidates review. The CLI rule revision binds the complete
discovery and review digest; it is an opaque content revision, not release order.
Exact safe invocations still rely on the surrounding Guard policy and installed
executable identity. They cannot suppress another rule or required safety floor.
Apply uses per-file replacement and rollback for ordinary errors, not a
crash-atomic filesystem transaction. After a crash, inspect Git status and the
`.hol-guard-extension-authoring.lock` before any retry.
