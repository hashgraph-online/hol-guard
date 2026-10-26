# Platform arm inventory

Guard's security decisions are written against POSIX primitives: mode bits, `O_NOFOLLOW`,
uid ownership, socket directories. Where a primitive has no Windows equivalent the code
takes a `#[cfg(not(unix))]` arm. Those arms decide real behaviour on the platform most of
Guard's test suite never compiles, so they need standing review rather than a reader
noticing them.

Two gaps shipped this way before the inventory existed:

- `rust/crates/guard-runtime/src/hook_direct_contained.rs` — the venv-activation route added
  in #5397 is `#[cfg(unix)]`, and its test file carries `#![cfg(unix)]`, so the Windows arm
  is never compiled into a test binary. A Windows user running
  `source .venv/bin/activate && pytest -q` got an approval prompt.
- `rust/crates/guard-command/src/pretool/contained_wrapper.rs` — `sibling_project_root` from
  #5200 has the same shape, with the same consequence for a sibling-project `node` command.

Neither was a regression and neither was visible in CI: the unix-gated tests passed, and
there was nothing on the non-unix side to fail.

## What the gate does

`scripts/ci/platform_arm_inventory.py` extracts every non-Unix behaviour arm from
`rust/crates/*/src` and requires a reviewed verdict and a written reason for each in
`ci/platform_arms.json`.

An arm is in scope when its predicate names `unix` and compiles off Unix. The predicate is
parsed and evaluated, not matched as text, so `not(unix)`, `not(any(unix, windows))` and
`all(not(unix), feature = "x")` are all found: no spelling of the same condition gets past
the gate, and an unknown atom or an unparseable predicate evaluates true, so the gate
over-collects rather than missing an arm.

`cfg!(..)` expressions are read too, in either polarity. `if cfg!(not(unix))` and
`if !cfg!(unix)` are the same platform difference as an attribute, and unlike an attribute
they leave no second item for the gate to find on its own. Inline `#[cfg(test)] mod tests`
extents are skipped, so a `cfg!(unix)` inside a test is not recorded as behaviour.

Each arm is keyed on its file and its normalised declaration, and every arm carries a
fingerprint of the source behind it — a declaration's body as much as a bare block's, since a
stub that fails closed can be rewritten into one that returns `true` under the reason that was
written for the old behaviour. The fingerprint ends where the item does, at the brace that
closes a body or at the `;` of a `mod` or `use` that has none, so an arm is not keyed on
whatever follows it. CI fails when an arm appears with no entry, when an entry names an arm
that no longer exists, when an arm's cfg predicate changes under an existing entry, or when
the source behind a reviewed arm changes — a verdict describes what the code does, so
rewriting the code retires the verdict.

A purely static "this `#![cfg(unix)]` test file covers a module with a `#[cfg(not(unix))]`
arm" lint was tried first and does not work: tests live in sibling `*_tests.rs` files and in
crate-level `tests/`, so a strict same-file rule flags most of the tree and a loose text match
lets `contained_wrapper.rs` through. Reachability from a test to a specific arm is not
decidable by grep. Requiring a reviewer's sentence per arm is.

```bash
python3 scripts/ci/platform_arm_inventory.py --root .      # the CI check
python3 scripts/ci/platform_arm_inventory.py --write       # seed entries for new arms
```

`--write` seeds a new arm as `windows-unsupported` with the note `unreviewed`, which the gate
rejects. Replace both fields with what you actually concluded. `--write` also resets an entry
whose cfg predicate or block fingerprint moved, for the same reason.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `posix-primitive` | The guarded thing only exists on POSIX, so there is nothing for the other arm to check. |
| `windows-equivalent` | The non-Unix arm enforces the same property by another mechanism. |
| `windows-unsupported` | The capability is not available on the platform and the arm reports that, rather than allowing the operation. |
| `windows-permissive` | The arm is weaker than the Unix one: a check the Unix side makes is skipped. The note must say what is skipped and what still holds. |
| `other-platform` | `all(not(unix), not(windows))` — a fallback for platforms Guard does not ship to. |

The note is the deliverable. A verdict with no reason is the state that let the two gaps
above ship.

## Current standing

196 arms, all reviewed: 68 `windows-unsupported`, 43 `windows-equivalent`, 40
`posix-primitive`, 30 `other-platform`, 15 `windows-permissive`.

The first pass of this gate matched `not(unix)` as text against attributes only and found
155. Evaluating the predicate and reading `cfg!` expressions found 40 more that were deciding
Windows behaviour with nobody having looked at them: 25 `not(any(unix, windows))` stubs,
which a text match spells differently, and 15 runtime `cfg!` branches, which have no
attribute to match at all. One of the `cfg!` branches is permissive.

One permissive arm was closed in this change: `sed_edits.rs::executable` reviewed an in-place
`sed` of an executable file by its mode bits on Unix and skipped the review entirely off
Unix, so rewriting a `.ps1`, `.bat`, `.cmd` or `.exe` in place was silent on Windows. It now
reads the name the way Win32 opens it — trailing dots and spaces trimmed, so `tool.exe.` does
not read as extensionless — against the shared `WINDOWS_PROGRAM_EXTENSIONS` list.

The fifteen that remain, each with the check it skips. None is an open hole on its own —
every one sits behind another condition that still holds — but each is a place where Windows
is enforcing less than macOS and Linux:

| Arm | Skipped on Windows |
| --- | --- |
| `hook_adapter_paths.rs::resolve_host` | No `GetFinalPathNameByHandle`, so a junction that aliases into a trusted root still reads as inside it. |
| `codex_output_pathspecs.rs::executable` | No mode probe; the resolved Git path always reads as executable. Canonicalisation onto the host's own Git binary still applies. |
| `github_conversation_files.rs::single_link` | Hard-link count skipped; `number_of_links` needs `GetFileInformationByHandle`, which stable `MetadataExt` does not expose. Size and regular-file bounds still apply. |
| `kubeconfig_trust.rs::outside_agent_trees` | Group/other-writable mode mask skipped; closing it needs an ACL read. The file must still sit outside the agent trees and outside any repository. |
| `process_probes.rs::trusted_postgres_socket` | Socket-directory ownership walk skipped. Windows clients reach a local server over TCP loopback, where there is no socket directory. |
| `trusted_location.rs::agent_writable_loader_tree` | Agent-writable loader directories are not excluded on that ground; the enclosing condition still requires trust by another route. |
| `worktree_add_destination.rs::fixed_symlinks` | Only the leaf is checked; the Unix arm walks parents with a hop bound. Junctions do report as symlinks to `file_type`. |
| `runtime_read_paths.rs::open_runtime_file` | No `O_NOFOLLOW`; a reparse point on the runtime path is followed. The path is under the account's own installation directory. |
| `sfrs_gh_body_file_check.rs::ancestor_chain_for_uid` | uid ownership walk skipped; needs an ACL owner read. The candidate must still sit under the private root. |
| `shell_execution_context_support.rs::directory_is_readable` | No `access(R_OK\|X_OK, effective_ids=True)` equivalent; a real read failure surfaces later as an I/O error. |
| `shell_execution_context_support.rs::check_eaccess` | Same, for the eaccess probe. |
| `managed_resident_stop.rs::endpoint_is_contained` | Filesystem-socket containment does not apply; Windows residents use an authenticated loopback endpoint, with the stopped acknowledgement and the owner-lock probe standing in. |
| `git_execution_safety_binary.rs::exists_and_executable` | Mode probe skipped, so every existing path reads as runnable. Permissive in the safe direction: the callers use it to decide whether a path *could* run, and treating more paths as runnable widens review rather than admitting a command. |
| `workspace_review_claim_index.rs::sync_directories_before_commit` | Directory fsync, which Windows has no equivalent for, so the claim index commits unsynced. The shards are still persisted by the node writer, so the exposure is a claim lost to a crash, not a claim wrongly granted. Closable with `FlushFileBuffers` on the directory handles. |
| `guard-secure-fs/src/lib.rs::open_immutable_blob` | Device, inode, link count and write-mode comparison; the arm compares length and mtime and the caller pairs it with a `GetFileInformationByHandle` file-id check. The file id proves the descriptor is the file that was stat'd, not that the file is immutable, so a writable blob is admitted. The caller rehashes what it streams. Closable with a share-mode or read-only-attribute check at open. |

These fifteen are recorded, not fixed. Each needs a Win32 call Guard does not make
yet — `GetFileInformationByHandle`, `GetFinalPathNameByHandle`, `FlushFileBuffers`, or an ACL
read — and each is a separate change with its own Windows test. The inventory is where they
stay visible.

## Adding an arm

1. Write the arm.
2. `python3 scripts/ci/platform_arm_inventory.py --write`.
3. Replace the seeded verdict and note. Say what the arm does instead, and if it is
   `windows-permissive`, what still holds.
4. If the verdict is `windows-permissive` and the gap is closable now, close it instead.
