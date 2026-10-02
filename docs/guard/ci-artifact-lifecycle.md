# Atomic source and generated evidence

Source changes and the generated files that bind them must arrive on `main` in
the same reviewed change. A green source PR must not depend on a later repair PR.

## Why this matters

The native command program binds compiler implementation inputs. The decision-diff
report binds Python, Rust, fixture, and documentation bytes. Changing a bound input
can make its evidence stale even when runtime decisions do not change.

The previous workflow rejected generated files from ordinary PRs, temporarily
regenerated native outputs during PR validation, and deferred report freshness.
After merge, main required the committed outputs to be current. A separate
review-required regeneration PR repaired them later. This guaranteed a red window
for source changes instead of preventing drift.

## Before a source PR merges

1. Review the canonical inputs and trust changes. Contributors can start with a
   source-only draft; a maintainer can prepare an upstream intake branch when a
   fork cannot accept maintainer edits.
2. Update the branch from main. Install the locked development environment and
   Rust toolchain, then regenerate all affected projections:

   ```sh
   uv sync --frozen --extra dev
   rustup toolchain install 1.88.0 --profile minimal
   uv run --no-sync python scripts/refresh_extension_artifacts.py
   uv run --no-sync python scripts/ci/check_generated_evidence.py
   uv run --no-sync python scripts/ci/verify_native_command_program.py \
     --compiler rust/target/release/guard-command-source
   ```

3. Inspect the generated diff, not just its hashes. Native behavior, action floors,
   known gaps, trust assignments, and fixture expectations still require review.
   Do not edit an oracle or lower an assertion to make regeneration pass.
4. Commit the generated outputs together with their source changes on this PR.
   Run the applicable native and Python tests, and wait for required checks and
   CodeOwner approval. Updating the source branch invalidates previous validation.

`scripts/refresh_extension_artifacts.py` generates the complete projection set,
rebuilds native binaries to match it, and verifies the result. The native verifier
is read-only by default, including when PR base metadata is provided. Its explicit
`--prepare --changed-from FULL_SHA` mode is for local previews only and must not be
used in a required CI gate.

## Checks and responsibilities

`generated-artifacts-guard / regen-owned-paths` runs on every PR without an author,
fork, or branch-prefix exemption. It reads committed files and checks that the
report binds current source and fixture bytes, its framing digest is correct, its
serialization is canonical, and packaged program/catalog copies match canonical
files. It never regenerates or changes expected evidence.

Required CI independently checks the real source compiler, including its embedded
program identity, before starting coverage shards. Full report reproduction and
environment-independence tests run on ordinary PRs as well as repair PRs and main.
The inexpensive binding check is not a replacement for those semantic checks.

The existing post-merge `extension-artifact-regen` workflow remains enabled to
repair inherited drift. Its repair PR still needs normal checks and maintainer
approval. Repeated main failures should be investigated, not cleared by skipping
freshness, adding retries, or treating pending regeneration as success.

## Merging concurrent changes

Regenerate against the branch state that will merge. A branch update that changes
bound inputs requires regenerated evidence and fresh checks. Do not merge an old
artifact-only PR over newer source changes without checking compatibility. Required
branch freshness or a tested merge queue must enforce the repository's chosen
integration policy; the scripts alone cannot serialize independent merges.
