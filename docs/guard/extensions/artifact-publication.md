# Extension artifact publication

Contributors continue to submit command sources, portable fixtures, reviewed
trust bindings, MCP sources, and optional listing metadata. Existing schemas,
fixture formats, authoring commands, and contribution paths remain supported.
External extensions still require explicit activation.

## Publication after merge

The existing main-only regeneration workflow generates and verifies the current
catalog, program, descriptors, and public directory. It publishes a snapshot
instead of committing those outputs or opening an artifact PR. This adds no
publication preflight or new required PR check.

Each successful source revision has a prerelease named
`extension-artifacts-<full-source-sha>`, containing:

- `extension-artifacts.zip`: directory catalogs, rendered documentation,
  descriptors, canonical command/MCP sources, listing metadata, and trust inputs.
- `extension-artifacts.v1.json`: source SHA, compiler implementation identity,
  catalog and program digests, archive digest, and every file's size and digest.

The release remains a draft until downloaded assets pass verification. A retry
can finish an interrupted draft. Published assets are never overwritten; a
different asset under the same source identity is an error. Snapshots do not
replace the latest stable Guard release. Failed publication leaves previously
published snapshots available. Workflow artifacts retain diagnostics separately.

Readers resolve a source revision first, then use its snapshot release. They
must validate the source identity and archive/file digests before consuming
the catalogs or descriptors. Read descriptor bytes from the same snapshot:
its generated descriptor may differ from a legacy tracked copy at that commit.
If a revision is not yet published, retain the last verified snapshot with its
original source identity; do not relabel old data as the new head.

## Package builds

Wheel and source-archive builds derive descriptors from the native compiler in
an ignored build directory. They do not overwrite tracked contributor files.
Source archives bind these outputs to their build inputs and can rebuild a wheel
without Cargo. Changed descriptor bytes invalidate the archive fingerprint.
Editable dependency installation retains its existing compiler-free behavior.

## Compatibility audit and retirement

The October 7, 2026 audit covered all 132 open PRs, including complete file lists
for PRs #3576 (484 files) and #2797 (1,848 files). It found overlapping groups:

| Legacy path | Open PRs that touch it |
| --- | ---: |
| Extension descriptors | 29 |
| Directory README | 18 |
| Directory catalogs | 11 |
| Aggregate trust map | 31 |

Directory compatibility paths remain tracked. Existing PRs may keep legacy directory edits;
package builds and snapshots regenerate authoritative outputs from sources.
The generated-path guard continues to reject reintroducing ignored native
program/catalog copies. Existing schema, fixture, and trust validation remain
in force; this migration does not waive unrelated validation failures.

Run `python scripts/audit_extension_projection_prs.py --output compatibility-audit.json`
to refresh the complete audit. Truncation is an error, not proof that a path is
unused. Retire a tracked projection only after a fresh audit finds no affected
open PRs and every reader of that path has migrated to snapshots. Until then,
repository-content readers retain the last committed compatibility copy; they
must migrate to snapshots to receive subsequent generated directory updates.

No contributor refactor, automatic branch rewrite, or mandatory rebase is part
of this transition. Maintainers own compatibility cleanup after readers and
existing PRs have migrated.

## Generated trust map

The aggregate trust map is no longer tracked, including as a compatibility
copy. Open contribution PRs must drop aggregate edits and retain their reviewed
per-extension bindings. CI rejects adding the shared map back, including from
regeneration PRs.

Rust builds and source runtimes read reviewed bindings. Package builds and
snapshot publication derive their maps from those bindings. Build outputs use
the ignored `contracts/extensions/build-trust-class-map.v1.json`; release staging
derives packaged trust directly. Installed and frozen runtimes read the packaged
map, without a fallback to a repository aggregate. Unbound canonical
contributions default to external and still require explicit activation.
