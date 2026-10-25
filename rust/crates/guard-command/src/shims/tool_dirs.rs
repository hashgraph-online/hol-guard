//! Well-known package-manager directories a launcher-provided PATH leaves out.
//!
//! The shim itself finds the real binary on the PATH of the shell that runs it,
//! so protection works wherever a shim is installed. Detection is different: it
//! decides which managers exist and therefore which shims get installed, and it
//! runs in the long-lived daemon. The daemon inherits the PATH of whatever
//! started it, and a desktop or IDE launcher hands it the bare system PATH. A
//! machine whose managers live under Homebrew, nvm, cargo, bun or uv then looks
//! as if it had almost none.
//!
//! The daemon marks its requests with [`TOOL_DIRS_ENV`]; only then does the
//! search widen. The caller's own PATH is always searched first, an explicit
//! `path_env` is searched alone, and the directories are only looked at, never
//! added to any environment a manager runs in. Windows keeps its own search
//! model and is left unchanged.

use super::{ShimContext, ShimFacts};

/// Request environment key the daemon sets to `1` to widen the search.
pub(crate) const TOOL_DIRS_ENV: &str = "HOL_GUARD_SHIM_TOOL_DIRS";

/// Home-relative directories, searched ahead of the system ones so a user's own
/// install wins over a system copy, as it does on a conventional shell PATH.
const HOME_TOOL_DIRS: [&str; 18] = [
    ".local/bin",
    ".cargo/bin",
    ".bun/bin",
    ".volta/bin",
    ".local/share/pnpm",
    "Library/pnpm",
    ".yarn/bin",
    ".config/yarn/global/node_modules/.bin",
    ".asdf/shims",
    ".local/share/mise/shims",
    ".pyenv/shims",
    ".rbenv/shims",
    ".nodenv/shims",
    ".sdkman/candidates/gradle/current/bin",
    ".sdkman/candidates/maven/current/bin",
    ".composer/vendor/bin",
    ".config/composer/vendor/bin",
    "go/bin",
];

/// Directories holding one subdirectory per installed version, each with the
/// binaries under a fixed suffix.
const VERSIONED_TOOL_ROOTS: [(&str, &str); 3] = [
    (".nvm/versions/node", "bin"),
    (".local/share/fnm/node-versions", "installation/bin"),
    (
        "Library/Application Support/fnm/node-versions",
        "installation/bin",
    ),
];

/// Absolute directories package managers install into by convention.
const SYSTEM_TOOL_DIRS: [&str; 6] = [
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/usr/local/go/bin",
    "/home/linuxbrew/.linuxbrew/bin",
    "/opt/local/bin",
    "/snap/bin",
];

/// Versions looked at per root; the newest few cover every realistic install.
const MAX_VERSIONS_PER_ROOT: usize = 8;

impl ShimContext {
    /// Whether this request asked for the widened search.
    pub(crate) fn tool_dirs_enabled(&self) -> bool {
        !self.facts.windows
            && self.facts.environ.get(TOOL_DIRS_ENV).map(String::as_str) == Some("1")
    }

    /// The PATH real binaries are searched on: an explicit `path_env` as given,
    /// otherwise the process PATH followed by the well-known directories that
    /// exist and are not already on it.
    pub(crate) fn search_path(&self, path_env: Option<&str>) -> String {
        if let Some(explicit) = path_env {
            return explicit.to_owned();
        }
        let base = self.env_path();
        if !self.tool_dirs_enabled() {
            return base.to_owned();
        }
        let facts = &self.facts;
        let present: Vec<String> = base
            .split(self.pathsep())
            .filter(|entry| !entry.is_empty())
            .map(|entry| facts.norm(entry))
            .collect();
        let mut path = base.to_owned();
        for directory in discovered_tool_dirs(facts) {
            if present.contains(&facts.norm(&directory)) {
                continue;
            }
            if !path.is_empty() {
                path.push(self.pathsep());
            }
            path.push_str(&directory);
        }
        path
    }
}

fn discovered_tool_dirs(facts: &ShimFacts) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();
    if facts.is_abs(&facts.home) {
        for relative in HOME_TOOL_DIRS {
            candidates.push(facts.join(&facts.home, relative));
        }
        for (root, suffix) in VERSIONED_TOOL_ROOTS {
            candidates.extend(versioned_dirs(facts, root, suffix));
        }
    }
    candidates.extend(SYSTEM_TOOL_DIRS.iter().map(|path| (*path).to_owned()));
    candidates
        .into_iter()
        .filter(|directory| facts.is_dir(directory))
        .collect()
}

fn versioned_dirs(facts: &ShimFacts, root: &str, suffix: &str) -> Vec<String> {
    let root = facts.join(&facts.home, root);
    let Ok(entries) = std::fs::read_dir(facts.fs_path(&root)) else {
        return Vec::new();
    };
    let mut versions: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    newest_first(&mut versions);
    versions.truncate(MAX_VERSIONS_PER_ROOT);
    versions
        .into_iter()
        .map(|version| facts.join(&facts.join(&root, &version), suffix))
        .collect()
}

/// Numeric components of a version directory name such as `v22.4.0`, so that
/// `v22` outranks `v9` where a plain string comparison would not.
fn version_key(name: &str) -> Vec<u64> {
    name.trim_start_matches(['v', 'V'])
        .split(|character: char| !character.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .map(|part| part.parse().unwrap_or(u64::MAX))
        .collect()
}

fn newest_first(versions: &mut [String]) {
    versions.sort_unstable_by(|left, right| {
        version_key(right)
            .cmp(&version_key(left))
            .then_with(|| right.cmp(left))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ordered(names: &[&str]) -> Vec<String> {
        let mut versions: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        newest_first(&mut versions);
        versions
    }

    #[test]
    fn a_two_digit_major_outranks_a_one_digit_major() {
        assert_eq!(
            ordered(&["v9.11.2", "v22.4.0", "v10.0.0", "v18.20.0"]),
            ["v22.4.0", "v18.20.0", "v10.0.0", "v9.11.2"]
        );
    }

    #[test]
    fn minor_and_patch_are_compared_as_numbers() {
        assert_eq!(
            ordered(&["v20.9.0", "v20.10.0", "v20.10.1"]),
            ["v20.10.1", "v20.10.0", "v20.9.0"]
        );
    }

    #[test]
    fn a_name_without_digits_sorts_last() {
        assert_eq!(ordered(&["system", "v8.0.0"]), ["v8.0.0", "system"]);
    }

    #[test]
    fn the_cap_keeps_the_newest_versions_across_a_digit_boundary() {
        let mut versions: Vec<String> = (1..=12).map(|major| format!("v{major}.0.0")).collect();
        newest_first(&mut versions);
        versions.truncate(MAX_VERSIONS_PER_ROOT);
        assert_eq!(versions.first().map(String::as_str), Some("v12.0.0"));
        assert_eq!(versions.last().map(String::as_str), Some("v5.0.0"));
        assert_eq!(versions.len(), MAX_VERSIONS_PER_ROOT);
        assert!(versions.contains(&"v9.0.0".to_owned()));
        assert!(!versions.contains(&"v4.0.0".to_owned()));
    }

    #[test]
    fn every_directory_is_a_plain_relative_or_absolute_path() {
        for relative in HOME_TOOL_DIRS {
            assert!(
                !relative.starts_with('/') && !relative.ends_with('/'),
                "{relative}"
            );
        }
        for (root, suffix) in VERSIONED_TOOL_ROOTS {
            assert!(!root.starts_with('/') && !suffix.starts_with('/'), "{root}");
        }
        for absolute in SYSTEM_TOOL_DIRS {
            assert!(
                absolute.starts_with('/') && !absolute.ends_with('/'),
                "{absolute}"
            );
        }
    }

    #[test]
    fn the_common_homebrew_and_user_install_directories_are_covered() {
        for expected in ["/opt/homebrew/bin", "/usr/local/bin"] {
            assert!(SYSTEM_TOOL_DIRS.contains(&expected), "{expected}");
        }
        for expected in [".local/bin", ".cargo/bin", ".bun/bin", ".local/share/pnpm"] {
            assert!(HOME_TOOL_DIRS.contains(&expected), "{expected}");
        }
        assert!(VERSIONED_TOOL_ROOTS
            .iter()
            .any(|(root, _)| *root == ".nvm/versions/node"));
    }
}
