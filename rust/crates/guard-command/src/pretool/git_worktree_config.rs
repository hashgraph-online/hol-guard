//! Configuration and system attribute sources the `git worktree add` proof
//! judges before it lets a checkout run.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

#[derive(Default)]
pub(super) struct ConfigFacts {
    pub(super) hook_dirs: Vec<PathBuf>,
    pub(super) filters: bool,
    /// Every filter key is the one `git lfs install` writes globally.
    pub(super) only_standard_lfs: bool,
    pub(super) attributes_file: Option<String>,
    pub(super) attribute_source_override: bool,
    /// A hook manager's hooks directory below the repository root (Husky
    /// writes `core.hooksPath=.husky/_` into the repository configuration).
    pub(super) repository_hooks_path: Option<String>,
    /// Every `remote.<name>.fetch` refspec, by remote name as Git spells it.
    pub(super) remote_fetch: Vec<(String, String)>,
    /// `worktree.guessRemote` starts the branch `git worktree add <path>`
    /// creates from a remote-tracking branch of that name, not from `HEAD`.
    pub(super) guess_remote: bool,
}

/// `Some(None)` when a setting could run a program or redirect the checkout,
/// `None` when the listing cannot be read.
///
/// Git for macOS as shipped with Xcode and the Command Line Tools lists its
/// bundled `gitconfig` (the `osxkeychain` credential helper and
/// `init.defaultBranch`) with the scope `unknown`. Git reads that file before
/// the system, global and repository files, and the probe clears the
/// environment and passes no `--file` or `--blob`, so no repository or command
/// setting can carry that scope. It is judged as a system setting while it
/// comes first; an `unknown` entry after a user or repository entry is doubt.
pub(super) fn safe_worktree_config(output: &[u8], home: &Path) -> Option<Option<ConfigFacts>> {
    let output = std::str::from_utf8(output).ok()?;
    let mut facts = ConfigFacts {
        only_standard_lfs: true,
        ..ConfigFacts::default()
    };
    let mut past_system = false;
    // The last `core.hooksPath` value read, and whether the repository's own
    // configuration wrote it.
    let mut hooks_path: Option<(bool, String)> = None;
    let mut records = output.split('\0');
    while let Some(scope) = records.next() {
        if scope.is_empty() {
            continue;
        }
        let record = records.next()?;
        let (key, value) = record.split_once('\n')?;
        if let Some(remote) = remote_fetch_name(key) {
            facts
                .remote_fetch
                .push((remote.to_owned(), value.to_owned()));
        }
        let key = key.to_ascii_lowercase();
        match scope {
            "unknown" if past_system => return None,
            "unknown" | "system" => {}
            _ => past_system = true,
        }
        if key == "core.bare" && super::super::git_config::enabled_boolean(value) {
            return Some(None);
        }
        if key == "worktree.guessremote" {
            // The last value Git reads wins, exactly as it resolves the key.
            // Git reads the key as a boolean, where any non-zero integer and
            // an empty value are true, so only an explicit false clears it.
            facts.guess_remote = !super::super::git_config::disabled_boolean(value);
            continue;
        }
        let global_scope = matches!(scope, "global" | "system" | "unknown");
        // The bundled `unknown` scope keeps the stricter reading for settings
        // that run programs or pull in more files; a user's own global config
        // and the system config are an ordinary developer's.
        let user_scope = matches!(scope, "global" | "system");
        if key == "core.hookspath" {
            // Hook managers set this globally; the directory must exist and
            // hold no hook Git would run for this operation. A repository's
            // own file carries the same trust as the user's global one:
            // `git clone` never copies `.git/config`, so a `local` value was
            // written by this developer or a tool they ran. The directory it
            // names is read either way. A `worktree` or `command` value can
            // come from this very invocation, so it stays doubt - and Git
            // reads those last, so nothing later in the listing retires one.
            if !global_scope && scope != "local" {
                return Some(None);
            }
            // Git consults one hooks path: the last value it is given. An
            // earlier value names a directory this checkout never reads, so
            // it is judged only once the listing ends and the effective value
            // is known. Judging it in place sent `worktree add` to review
            // over a directory Git had already been told to ignore.
            hooks_path = Some((scope == "local", value.to_owned()));
            continue;
        }
        if key.starts_with("filter.") {
            // Git LFS installs these globally; they only act where an
            // attribute assigns a filter, which the caller then rules out.
            if !global_scope {
                return Some(None);
            }
            facts.filters = true;
            facts.only_standard_lfs &=
                super::super::git_remote_ops::pull::standard_lfs(&key, &[value.to_owned()]);
            continue;
        }
        if key == "core.attributesfile" {
            facts.attributes_file = Some(value.to_owned());
            continue;
        }
        if key.starts_with("attr.") {
            facts.attribute_source_override = true;
            continue;
        }
        // `worktree add` and each probe below use built-in commands, local
        // refs, and no diff/editor operation. None of them asks Git for a
        // credential, so no credential helper runs, whatever its scope: the
        // branch the checkout starts from is resolved against the refs this
        // repository already holds. A `local` value carries the same trust as
        // the user's global one for that reason and for the reason
        // `core.hooksPath` does: `git clone` never copies `.git/config`, so a
        // repository value was written by this developer or a tool they ran.
        // A `worktree` or `command` value can come from this very invocation,
        // so it stays doubt.
        // The repository may not name further LFS programs for a filter
        // the user's own `git lfs install` set up.
        if !global_scope
            && key.starts_with("lfs.")
            && (key.starts_with("lfs.extension.")
                || key.starts_with("lfs.customtransfer.")
                || key.ends_with(".standalonetransferagent"))
        {
            return Some(None);
        }
        if key == "core.worktree"
            || (key == "core.fsmonitor" && !boolean_literal(value))
            || (matches!(
                key.as_str(),
                "core.sshcommand" | "core.gitproxy" | "core.askpass"
            ) && !user_scope)
            || key.starts_with("hook.")
            || (display_pager_setting(&key) && !display_pager_key(&key))
            || (key.starts_with("credential.") && !global_scope && scope != "local")
            || (key.starts_with("include") && (!user_scope || key.contains("onbranch:")))
            || (key.starts_with("extensions.") && !inert_extension(&key))
            || (key.starts_with("submodule.")
                && !matches!(key.as_str(), "submodule.recurse" | "submodule.fetchjobs"))
            || key.ends_with(".promisor")
            || key.ends_with(".partialclonefilter")
            || key.ends_with(".uploadpack")
            || key.ends_with(".receivepack")
        {
            return Some(None);
        }
    }
    if let Some((local, value)) = hooks_path {
        if local && super::super::git_hook_files::repository_relative_hooks_path(&value) {
            facts.repository_hooks_path = Some(value);
        } else {
            let Some(directory) = expand_config_path(&value, home)
                .and_then(|path| fs::canonicalize(path).ok())
                .filter(|path| path.is_dir())
            else {
                return Some(None);
            };
            facts.hook_dirs.push(directory);
        }
    }
    Some(Some(facts))
}

/// The remote a `remote.<name>.fetch` key names. Git compares the section and
/// variable without case and the remote name exactly.
fn remote_fetch_name(key: &str) -> Option<&str> {
    let lower = key.to_ascii_lowercase();
    if !lower.starts_with("remote.") || !lower.ends_with(".fetch") {
        return None;
    }
    key.get("remote.".len()..key.len() - ".fetch".len())
        .filter(|name| !name.is_empty())
}

fn display_pager_setting(key: &str) -> bool {
    key == "core.pager" || key.starts_with("pager.")
}

/// A pager starts only for a command that pages its output, and only on a
/// terminal. `worktree add` runs `worktree`, `reset` and `update-ref`, none
/// of which a display setting names, so `core.pager` and
/// `pager.<display command>` do nothing here whichever file sets them: a
/// repository that spells one is choosing how `git log` prints, not what this
/// checkout runs. Any other `pager.<command>` key stays reviewed.
fn display_pager_key(key: &str) -> bool {
    const DISPLAY: &[&str] = &[
        "diff", "log", "show", "blame", "annotate", "status", "grep", "stash", "tag", "branch",
        "shortlog", "reflog",
    ];
    key == "core.pager"
        || key
            .strip_prefix("pager.")
            .is_some_and(|command| DISPLAY.contains(&command))
}

/// Repository format facts that name no program and add no object source.
fn inert_extension(key: &str) -> bool {
    matches!(
        key,
        "extensions.worktreeconfig" | "extensions.objectformat" | "extensions.refstorage"
    )
}

fn boolean_literal(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "false" | "yes" | "no" | "on" | "off" | "1" | "0"
    )
}

/// An absolute path or `~/...` under the session home; anything else is doubt.
pub(super) fn expand_config_path(value: &str, home: &Path) -> Option<PathBuf> {
    if value.is_empty() || value.contains(['\0', '\n', '\r']) {
        return None;
    }
    if let Some(rest) = value.strip_prefix("~/") {
        return (!rest.is_empty()).then(|| home.join(rest));
    }
    let path = Path::new(value);
    path.is_absolute().then(|| path.to_path_buf())
}

/// The system attribute files this Git reads. Git 2.42 and later name the
/// file through `git var GIT_ATTR_SYSTEM`. Older releases, including the Git
/// that Xcode and the Command Line Tools install as `/usr/bin/git`, reject
/// that variable as a usage error; for them every place such a build reads
/// system attributes from is listed instead: `/etc/gitattributes`, and the
/// `etc/gitattributes` and `share/git-core/gitattributes` files of the
/// install prefix that `git --exec-path` (`<prefix>/libexec/git-core`) names.
pub(super) fn system_attribute_files(
    base: &Command,
    leading: &[String],
    deadline: Instant,
) -> Option<Vec<PathBuf>> {
    let (status, system) =
        super::git_query(base, leading, ["var", "GIT_ATTR_SYSTEM"], deadline, 4096)?;
    if status.success() {
        let system = std::str::from_utf8(&system).ok()?.trim();
        if system.is_empty() || !Path::new(system).is_absolute() {
            return None;
        }
        return Some(vec![PathBuf::from(system)]);
    }
    // `git var` exits 129 for an unknown variable; any other failure is doubt.
    if status.code() != Some(129) {
        return None;
    }
    let (status, exec_path) = super::git_query(base, leading, ["--exec-path"], deadline, 4096)?;
    if !status.success() {
        return None;
    }
    let prefix = install_prefix(std::str::from_utf8(&exec_path).ok()?.trim())?;
    Some(vec![
        PathBuf::from("/etc/gitattributes"),
        prefix.join("etc/gitattributes"),
        prefix.join("share/git-core/gitattributes"),
    ])
}

/// `<prefix>` of a canonical `<prefix>/libexec/git-core` exec path.
fn install_prefix(exec_path: &str) -> Option<PathBuf> {
    if exec_path.is_empty() || exec_path.contains(['\0', '\n', '\r']) {
        return None;
    }
    let path = Path::new(exec_path);
    if !path.is_absolute() {
        return None;
    }
    let canonical = fs::canonicalize(path).ok()?;
    if !canonical.ends_with("libexec/git-core") {
        return None;
    }
    canonical.parent()?.parent().map(Path::to_path_buf)
}

#[cfg(test)]
#[path = "git_worktree_config_tests.rs"]
mod tests;
