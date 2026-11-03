# What Guard enforces on Windows

Guard's command review runs on Windows, macOS and Linux from the same native
runtime and the same catalog. One enforcement mechanism does not: the workspace
sandbox. This page states the difference plainly so release notes and support
answers do not claim more than the product does.

## The workspace sandbox is macOS and Linux only

`rust/crates/guard-command/src/pretool/workspace_contained.rs` runs a
confidently parsed local command inside a sandbox that denies network access,
denies the home directory, denies credentials, and write-denies `.git`
execution config and agent/editor paths. A command that the sandbox can bound
runs quietly instead of becoming a review prompt.

On Windows the module compiles its `#[cfg(not(unix))]` arms:

```rust
fn workspace_admissible(_cwd: &Path, _home: Option<&Path>) -> Option<PathBuf> {
    None
}
fn linux_workspace_sandbox_available() -> bool {
    false
}
```

No command is ever admitted to a workspace, so every command whose only quiet
route was containment falls through to review with
`native_workspace_containment_required`.

## Read-only containment does run on Windows

The workspace sandbox is not the only containment Guard has. The LPAC
AppContainer behind `guard-contained-process` runs a staged read-only snapshot
of the workspace, and the profiles built on it work on Windows: the contained
read fan-outs, the package and launcher profiles, and `pytest-readonly-v2`,
which runs a project's own test suite from a staged copy of its virtual
environment.

So the rule is narrower than "no containment on Windows". A command that a
profile can express runs quietly there. A command whose only quiet route was
the workspace sandbox — an arbitrary local program the parser read
confidently, with no profile that bounds what it reaches — becomes a review.

## What that costs a Windows user

Two shapes in the current Gauntlet catalog show the remaining gap:

- `omp-native-git-long-lived-clone-worktree-add`
- `omp-native-git-apply-check-tmp-patch`

These are not false positives. Guard has no mechanism on Windows that bounds
what those commands can reach, so review is the honest answer for them. Calling
them false positives would mean asking Guard to allow an unbounded local
program on the word of the parser alone.

`omp-native-shell-venv-activate-tests` was listed here as a third. It is no
longer a containment gap: `pytest-readonly-v2` is the mechanism that was
missing. The case still does not pass on Windows, for a reason that is not
Guard's — its command text is `source .venv/bin/activate && pytest -q`, and
`source` is not a Windows shell builtin, a Windows virtual environment
activates through `Scripts\activate`, and the Gauntlet fixture writes a
POSIX-shaped `.venv` with no interpreter under `Scripts\`. A Windows spelling
of that case needs its own case id and a Windows arm in the fixture.

### What `pytest-readonly-v2` does not cover on Windows

The profile runs the environment's own interpreter from a staged copy, so it
needs an environment the snapshot can carry whole. Two shapes it cannot, and
which fall back to review rather than failing inside the container:

- An environment built from hardlinked files, which is how `uv` installs
  packages out of its cache. The snapshot omits any workspace file with a
  second directory entry, because that entry may be another name for a
  withheld file such as `.env`; an environment staged with holes in it would
  fail on import rather than run.
- An environment that imports through an absolute path outside itself — a
  `.pth` line holding the path it was written with, or an `__editable__`
  finder from an editable install. The snapshot sits at a fresh root, so that
  path resolves to nothing inside it.

Both are planner refusals with a stated reason, not silent allows, and both
leave the run on the route it had before the profile existed.

## What would close the gap

A Windows equivalent of the *workspace* sandbox: an AppContainer or a Job
Object with a restricted token, bounding a command the parser read confidently
but that no profile describes, plus the path and network denials the macOS
profile expresses. Each profile that arrives instead — `pytest-readonly-v2` is
one — closes a named shape rather than the general case, which is why the list
above shrinks one entry at a time.

Containment is the largest platform difference but not the only one. Every
other `#[cfg(not(unix))]` arm in the Rust tree is listed, with a verdict and a
reason, in [the platform arm inventory](platform-arm-inventory.md), and CI
fails when a new one arrives unreviewed.

## How to state this in release notes

Say that Guard reviews and blocks on Windows with the same catalog and runtime,
that read-only containment profiles run there, and that silent *workspace*
containment is macOS and Linux only. Do not claim "same protection on every
platform" and do not count the two cases above as outstanding false
positives.
