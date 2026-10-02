# Build-owned resources and evidence

Contributors maintain canonical sources, schemas, trust policy and independent
behavioral expectations. Builds produce programs, catalogs, descriptors,
packaged copies and reports. Derived output is not committed. A source merge
must not depend on a later regeneration PR to become buildable.

## Native compilation

The host-only guard-command-build dependency compiles the exact native source
compiler implementation without a packaged default program. Its private
bootstrap configuration cannot evaluate a default program. The target build
script validates canonical JSON and the reviewed trust map with that compiler,
then writes program, catalog and compiler export bytes to Cargo OUT_DIR.
Runtime compilation embeds those bytes. No previous checked-in program or
repeated generation/rebuild loop is needed.

Source validation, duplicate-key and size rejection, native admission,
implementation binding and rule attestation remain active. The runtime never
invokes Python generation on a hook path. Its program remains immutable.

## Source installs and package builds

Install the pinned Rust toolchain, then use normal uv sync or Hatch builds.
The hook stages generated resources automatically. Editable installs stage
ignored package-resource files; wheels and source distributions explicitly
include the complete generated resource inventory. No manual synchronization
or generated-file commit is part of contributing.

The ignored build/guard-resources/manifest.json binds authored source inventory,
schemas, trust, generator code, locked native implementation and every output.
Reuse requires matching inputs, exact output inventory and matching bytes.
Source edits during preparation fail, incomplete builds cannot publish a
completed manifest, and removed extensions cannot survive in cached resources.
Installed-wheel tests never fall back to the source tree.

CI dependency installation may defer editable preparation until downloading
this run's producer output. Source tests validate resources before importing
Guard. Wheel and source-distribution builds never honor that deferral. This is
not a PR-only freshness exemption.

## Evidence and independent expectations

Decision reports are computed from the current native build under ignored
build/guard-evidence. Corpus and oracle inputs, action floors, native capability
contracts, known gaps and fixed cross-language cryptographic vectors remain
separately authored and reviewed. Reproducibility compares independent runs of
the same current inputs, including fresh processes with different environments.
It does not require changing source hashes to equal a committed old report.

Historical implementation identities in the native capability contract describe
the origin of its reviewed expectations. Current implementation bytes are bound
separately by each build and report. Expected decisions are never generated
from the implementation under test. Live catalog completeness and binding have
separate checks from the fixed cryptographic vectors.

## CI and directory consumers

PRs, pushes and release builds use the same native preparation and strict
verification. The existing generated-artifacts-guard / regen-owned-paths check
now requires derived output to remain outside the resulting Git tree, without
author or branch exemptions. There is no repository-writing artifact workflow,
pending-regeneration detector or script that rewrites test anchors.

CI's parallel public-directory job exports raw guard-extension-directory.json
with the pinned upload-artifact v7 action. Its envelope binds repository, exact
source commit, run, attempt, directory and generated descriptor bytes. The
portal accepts only a completed successful canonical main CI run. Weekly CI
refreshes retained artifacts for quiet branches; current-SHA failures retry
rather than labeling stale data current.

Deploy points-portal PR #6569 before this producer/deletion change. That reader
keeps legacy Git access for older revisions and preserves published profile
fingerprints. It independently verifies authored Git blobs and merged source
PRs for attribution. Generated logical descriptors do not confer authorship
or publisher authority.

## Required validation

Verify clean compilation without generated inputs; normal source installs and
wheel/sdist packaging; source-only add/edit/remove changes; malformed-source
rejection; output corruption and inventory failures; the independent corpus;
and complete installed-native qualification. Keep all required checks and
approval rules. Measure completed runs separately: removing synchronization
does not itself prove four-minute CI.
