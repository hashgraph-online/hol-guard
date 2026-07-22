# Skill directory identity

Guard treats a skill as a directory bundle, not as `SKILL.md` alone. Gemini,
Antigravity, and shared Codex/AIBOM discovery use the same v1 identity contract.
Hermes remains on its legacy primary-document identity until its separate
complete-input migration.

## Metadata contract

A complete inspection emits these related values:

- `content_hash`: SHA-256 of the exact primary `SKILL.md` body.
- `directory_hash`: SHA-256 of the canonical full-directory identity stream.
- `skillDirectoryIdentity`: an envelope with
  `schemaVersion: guard.skill-directory-identity.v1`, `status: complete`, the
  directory digest in `contentHash`, `entryCount`, `totalBytes`, and
  `reusable: true`.
- `versionInfo.contentHash`: the same complete directory digest.

Inventory uses the validated directory digest as the skill item's
`content_hash`, so a secondary-file or mode change changes the item and
snapshot identity. Guard also records a locally recomputed
`primaryContentHash`; it is distinct from the bundle identity and cannot be
supplied authoritatively by an adapter.

The three directory bindings (`directory_hash`,
`skillDirectoryIdentity.contentHash`, and `versionInfo.contentHash`) must agree.
Malformed or mismatched metadata is not promoted to a directory identity, and
an unverified bare `directory_hash` is removed from inventory metadata.

## Canonical stream

Inspection starts at the directory containing the primary `SKILL.md` and
accounts for every nested entry; there are no filename or cache-directory
exclusions. Records are ordered by canonical `/`-separated relative path and
bind:

- the relative path and entry type;
- security-relevant POSIX mode bits, including executable state;
- the complete byte length and SHA-256 digest of each accepted regular file;
- directory records, including empty directories; and
- for an accepted non-primary, in-tree file symlink, the link spelling,
  canonical target path, target type, mode, length, and complete target digest.

The stream excludes mtime, inode, device number, and filesystem enumeration
order. Therefore touching a file without changing its accepted identity is
stable, while changing a path, type, bytes, executable mode, or symlink target
changes the directory digest.

A directory symlink is never recursively traversed during discovery. Skill-root
and nested directory symlinks are reported as incomplete and non-reusable. The
primary `SKILL.md` must be a regular file; contained regular-file symlinks are
accepted only for secondary entries. Broken links,
links outside the skill directory, loops, special files, reparse-point
ambiguity, path/case collisions, unreadable entries, and observed read races
make the inspection incomplete instead of silently omitting an entry.

## Resource limits and incomplete results

Both grouping-path discovery and the shared inspector accept at most 32 nested
path components and 4,096 entries. Discovery stops at a primary document and
hands its full subtree to the inspector, so the limits apply without first
materializing an unbounded directory. The inspector accepts
128 MiB per regular file, and 256 MiB of total bytes read. Symlink target reads
also consume the total-byte budget, so aliases cannot amplify unbounded hashing
work. These defaults are defined by `DEFAULT_SKILL_DIRECTORY_LIMITS` in
`guard/skill_directory_identity.py` and are applied before a result can be
marked complete. Operating-system path/symlink resolution errors and reaching a
Guard resource bound produce a typed reason rather than a prefix hash.

An incomplete inspection emits `status: incomplete`, `reusable: false`, a safe
reason, observed counts, and a deterministic `incompleteStateHash`; it does not
emit `directory_hash`. The state hash keeps repeated observation of the same
incomplete state stable for inventory and the runner's approve-then-redetect
flow, but it is never reusable approval authority. `versionInfo` binds this
incomplete marker rather than claiming a complete bundle digest. The consumer
applies a `require-reapproval` floor and will neither accept nor claim saved
approval evidence for a marked incomplete, non-reusable, malformed, or
mismatched identity. An exact fresh approval can still follow the normal
explicit authority path.

## Primary content and previews

Directory identity reads and hashes all accepted bytes. Bounded document
analysis and display previews remain separate and may report truncation without
weakening the bundle identity.

AIBOM primary-content upload remains intentionally narrower: it uploads only
the exact `SKILL.md` body and labels it with the trusted primary digest. The
inventory item's directory-wide hash is never used as the body hash, and
scripts, references, templates, assets, and other supplementary files are never
uploaded by this path. The upload path rereads the bounded body and verifies its
digest immediately before serialization.
