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

## What that costs a Windows user

The shapes that run silently on macOS and ask on Windows are the ones whose
safety came from the sandbox rather than from their own proof. Three in the
current Gauntlet catalog show it:

- `omp-native-git-long-lived-clone-worktree-add`
- `omp-native-git-apply-check-tmp-patch`
- `omp-native-shell-venv-activate-tests`

These are not false positives. Guard has no mechanism on Windows that bounds
what the command can reach, so review is the honest answer for them. Calling
them false positives would mean asking Guard to allow an unbounded local
program on the word of the parser alone.

Everything that proves itself without the sandbox behaves the same on Windows
as it does elsewhere: recognised read-only commands, the contained read
fan-outs, the package and launcher profiles, and every deny path.

## What would close the gap

A Windows containment mechanism — a Job Object with a restricted token, or an
AppContainer profile — plus the path and network denials the macOS profile
expresses. That is a port of the whole containment layer, not a configuration
change, and it is not in the current release.

## How to state this in release notes

Say that Guard reviews and blocks on Windows with the same catalog and runtime,
and that silent workspace containment is macOS and Linux only. Do not claim
"same protection on every platform" and do not count the three cases above as
outstanding false positives.
