//! The search path screen for the `git worktree add` chain proof. Once the
//! chain has entered or routed into the new checkout, a bare program name is
//! looked up again, so every search path entry that could name a folder the
//! checked-out ref fills withholds the proof.

use std::path::{Path, PathBuf};

/// Whether every entry of the search path the command runs with is absolute
/// and lies outside the checkout the add creates. Once the `cd` has entered
/// the new checkout a relative entry names one of its folders, whose
/// contents come from the ref it checks out, so a bare program name after
/// the `cd` could run what that ref supplies. An absolute entry inside the
/// destination says the same thing from the other side: the add refuses an
/// existing destination, so nothing fills that folder but the checkout.
pub(super) fn search_path_outside(
    destination: &Path,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    screened_search_path(destination, None, execution_environment)
}

/// The same screen for a chain that routes Git into the checkout with `-C`
/// instead of entering it. Those steps look their `git` up on the search
/// path exactly as the steps after a `cd` do, so an entry the new checkout
/// supplies decides what they run either way.
///
/// The shell's own directory does not move here, so a relative entry can be
/// read against it and screened like any other. After a `cd` it would
/// resolve inside the checkout whatever it is spelled, which is why the
/// entered form has no base to offer and refuses one outright.
pub(super) fn routed_search_path_outside(
    destination: &Path,
    base: Option<&Path>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    screened_search_path(destination, base, execution_environment)
}

/// Whether every search path entry names a folder outside the new checkout.
/// `base` is the directory a relative entry is read against, and `None`
/// refuses a relative entry because nothing here can say where it lands.
fn screened_search_path(
    destination: &Path,
    base: Option<&Path>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(search_path) = execution_environment
        .map(|environment| std::ffi::OsString::from(&environment.path))
        .or_else(|| std::env::var_os("PATH"))
    else {
        return false;
    };
    std::env::split_paths(&search_path).all(|directory| {
        // On Windows an empty entry names no folder: Git Bash drops it when
        // it converts the search path, and Git skips it when it looks a
        // program up, so neither reads it as the shell's own directory.
        if cfg!(windows) && directory.as_os_str().is_empty() {
            return true;
        }
        if directory.is_absolute() {
            return !entry_in_checkout(&directory, destination);
        }
        // An empty entry is the shell's own directory, and `join` on an
        // empty path returns the base, so both read the same way.
        base.is_some_and(|base| !entry_in_checkout(&base.join(&directory), destination))
    })
}

/// Whether one search path entry names a folder of the new checkout. The
/// entry is compared the way the shell will read it, not as it is spelled:
/// an entry the shell cannot be shown to name a folder outside the
/// destination counts as inside it.
fn entry_in_checkout(directory: &Path, destination: &Path) -> bool {
    normalized_entry(directory).is_none_or(|entry| !outside_checkout(&entry, destination))
}

/// Whether the entry can be shown to name a folder the new checkout does
/// not hold. Components are compared one at a time with their letters
/// folded down, so that two spellings of one folder compare equal on a
/// filesystem that ignores case. macOS and Windows both ship one by
/// default, and there `<parent>/APP-FLAT/bin` is a folder of the checkout
/// `git worktree add ../app-flat` creates, however it is written.
///
/// A pair of components that still differ is a difference to rely on only
/// while one of them is ASCII. APFS stores a name in whatever normalization
/// it was written with and reads every normalization of it as the same
/// folder, so `cafe` followed by U+0301 and `caf` plus U+00E9 name one
/// directory while comparing unequal, and folding case does not bring them
/// together. Where both components carry a character outside ASCII, the
/// difference therefore proves nothing and the entry reads as inside the
/// checkout, which withholds the proof and leaves the chain reviewed. An
/// ASCII name is its own canonical form in every normalization, so a
/// difference from one is a real difference whatever the other holds.
///
/// An entry that stops above the destination is outside it too: the add
/// creates the destination and nothing above it, so the ref it checks out
/// does not fill an ancestor.
fn outside_checkout(entry: &Path, destination: &Path) -> bool {
    let mut components = entry.components();
    for expected in destination.components() {
        let Some(actual) = components.next() else {
            return true;
        };
        if actual == expected {
            continue;
        }
        let actual = actual.as_os_str().to_string_lossy();
        let expected = expected.as_os_str().to_string_lossy();
        // Lowercasing alone leaves a character that is already lowercase but
        // folds onto ASCII, such as U+017F long s, apart from the ASCII
        // letter a case-ignoring filesystem reads it as. Going up first and
        // back down brings the pair together before the ASCII rule applies.
        let folded = |name: &str| name.to_uppercase().to_lowercase();
        if folded(&actual) == folded(&expected) {
            continue;
        }
        return actual.is_ascii() || expected.is_ascii();
    }
    false
}

/// A search path entry resolved the way the kernel will resolve it once the
/// add has run: the deepest ancestor that exists now is canonicalized,
/// which follows every symbolic link above the entry and every `..` in it,
/// and the names still to be created are applied to the result.
///
/// The destination does not exist until the add runs, so an entry inside it
/// cannot be resolved on disk and a component-wise comparison of the raw
/// entry reads a spelling the shell never uses: `<repository>/../app-flat/bin`
/// and `<link-to-parent>/app-flat/bin` both name a folder of the checkout
/// while sharing no component with it. An entry that cannot be resolved at
/// all -- a dangling link, a name whose tail still holds `..`, a path with
/// no existing ancestor -- returns `None` and is treated as inside the
/// checkout, because nothing here can say where the shell would land.
fn normalized_entry(directory: &Path) -> Option<PathBuf> {
    let mut existing = directory.to_path_buf();
    let mut missing = Vec::new();
    while std::fs::symlink_metadata(&existing).is_err() {
        missing.push(existing.file_name()?.to_owned());
        if !existing.pop() {
            return None;
        }
    }
    let mut resolved = std::fs::canonicalize(&existing).ok()?;
    resolved.extend(missing.iter().rev());
    Some(resolved)
}
