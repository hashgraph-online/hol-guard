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
    let mut records = output.split('\0');
    while let Some(scope) = records.next() {
        if scope.is_empty() {
            continue;
        }
        let record = records.next()?;
        let (key, value) = record.split_once('\n')?;
        let key = key.to_ascii_lowercase();
        match scope {
            "unknown" if past_system => return None,
            "unknown" | "system" => {}
            _ => past_system = true,
        }
        if key == "core.bare" && super::super::git_config::enabled_boolean(value) {
            return Some(None);
        }
        let global_scope = matches!(scope, "global" | "system" | "unknown");
        if key == "core.hookspath" {
            // Hook managers set this globally; the directory must exist and
            // hold no hook Git would run for this operation.
            if !global_scope {
                return Some(None);
            }
            let Some(directory) = expand_config_path(value, home)
                .and_then(|path| fs::canonicalize(path).ok())
                .filter(|path| path.is_dir())
            else {
                return Some(None);
            };
            facts.hook_dirs.push(directory);
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
        // refs, and no diff/editor operation. A global or system credential
        // helper, such as the `osxkeychain` helper Git for macOS installs, is
        // not consulted for this local-ref operation; retain the deny floor
        // for repository-scoped helpers and execution-capable settings.
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
            || key == "core.fsmonitor"
            || key == "core.sshcommand"
            || key == "core.gitproxy"
            || key == "core.askpass"
            || key == "core.pager"
            || key.starts_with("hook.")
            || key.starts_with("pager.")
            || (key.starts_with("credential.") && !global_scope)
            || key.starts_with("include")
            || key.starts_with("extensions.")
            || key.starts_with("submodule.")
            || key.ends_with(".promisor")
            || key.ends_with(".partialclonefilter")
            || key.ends_with(".uploadpack")
            || key.ends_with(".receivepack")
        {
            return Some(None);
        }
    }
    Some(Some(facts))
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
mod tests {
    use super::*;

    fn listing(entries: &[(&str, &str, &str)]) -> Vec<u8> {
        let mut output = Vec::new();
        for (scope, key, value) in entries {
            output.extend_from_slice(format!("{scope}\0{key}\n{value}\0").as_bytes());
        }
        output
    }

    fn judged(entries: &[(&str, &str, &str)]) -> Option<Option<ConfigFacts>> {
        safe_worktree_config(&listing(entries), Path::new("/nonexistent-home"))
    }

    #[test]
    fn bundled_macos_config_is_judged_as_system_config() {
        let facts = judged(&[
            ("unknown", "credential.helper", "osxkeychain"),
            ("unknown", "init.defaultbranch", "main"),
            ("global", "user.name", "Example"),
            ("local", "core.bare", "false"),
        ]);
        assert!(matches!(facts, Some(Some(_))));
    }

    #[test]
    fn bundled_scope_keeps_execution_settings_reviewed() {
        for key in [
            "core.fsmonitor",
            "core.pager",
            "core.sshcommand",
            "hook.post-checkout.command",
            "pager.log",
            "include.path",
        ] {
            let facts = judged(&[("unknown", key, "/opt/example/run")]);
            assert!(matches!(facts, Some(None)), "{key}");
        }
    }

    #[test]
    fn bundled_scope_after_repository_settings_is_doubt() {
        let facts = judged(&[
            ("local", "core.bare", "false"),
            ("unknown", "credential.helper", "osxkeychain"),
        ]);
        assert!(facts.is_none());
    }

    #[test]
    fn repository_credential_helper_and_filter_stay_reviewed() {
        assert!(matches!(
            judged(&[("local", "credential.helper", "osxkeychain")]),
            Some(None)
        ));
        assert!(matches!(
            judged(&[("local", "filter.lfs.smudge", "git-lfs smudge -- %f")]),
            Some(None)
        ));
        assert!(matches!(
            judged(&[("worktree", "core.hookspath", "/opt/hooks")]),
            Some(None)
        ));
    }

    #[test]
    fn standard_lfs_filter_is_recognised() {
        let Some(Some(facts)) = judged(&[
            ("global", "filter.lfs.clean", "git-lfs clean -- %f"),
            ("global", "filter.lfs.smudge", "git-lfs smudge -- %f"),
            ("global", "filter.lfs.process", "git-lfs filter-process"),
            ("global", "filter.lfs.required", "true"),
        ]) else {
            panic!("standard LFS filter rejected");
        };
        assert!(facts.filters && facts.only_standard_lfs);
        let Some(Some(facts)) =
            judged(&[("global", "filter.lfs.smudge", "/opt/example/smudge %f")])
        else {
            panic!("global filter rejected");
        };
        assert!(facts.filters && !facts.only_standard_lfs);
    }

    #[test]
    fn install_prefix_needs_a_libexec_git_core_exec_path() {
        let root = std::env::temp_dir().join(format!(
            "guard-worktree-prefix-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        ));
        let exec_path = root.join("usr/libexec/git-core");
        fs::create_dir_all(&exec_path).expect("exec path");
        let canonical_root = fs::canonicalize(&root).expect("root");
        assert_eq!(
            install_prefix(exec_path.to_str().expect("utf-8")),
            Some(canonical_root.join("usr"))
        );
        assert_eq!(install_prefix(root.to_str().expect("utf-8")), None);
        assert_eq!(install_prefix("usr/libexec/git-core"), None);
        fs::remove_dir_all(root).ok();
    }
}
