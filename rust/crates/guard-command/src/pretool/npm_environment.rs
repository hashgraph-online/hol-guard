//! Inherited variables that npm-family proofs can admit.
//!
//! Developer shells often export `npm_config_cache` and a loader search path
//! such as `~/.local/lib`. Neither moves the registry, adds a configuration
//! file or loads a hook, so refusing them would review every install and read
//! on those hosts without stopping anything.

use guard_contracts::GuardExecutionEnvironmentV1;
use std::path::Path;

/// npm keys that only move npm's content-addressed cache or change what it
/// prints. Packages read from the cache are still checked against the
/// lockfile's integrity hashes.
const INERT_NPM_KEYS: &[&str] = &[
    "cache",
    "color",
    "fund",
    "loglevel",
    "progress",
    "update_notifier",
];

/// Whether `name` is an `npm_config_*` variable naming an inert key.
pub(super) fn inert_npm_config_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase().replace('-', "_");
    lower
        .strip_prefix("npm_config_")
        .is_some_and(|key| INERT_NPM_KEYS.contains(&key))
}

/// Whether `name` is a loader search path the hook stamped whose every entry
/// is a trusted directory outside each of `roots`. Injection variables such
/// as `LD_PRELOAD` are never stamped, so they never pass.
pub(super) fn trusted_stamped_loader(
    environment: &GuardExecutionEnvironmentV1,
    name: &str,
    home: Option<&str>,
    roots: &[&str],
) -> bool {
    let Some(home) = home else {
        return false;
    };
    !roots.is_empty()
        && environment
            .library_search_paths
            .get(name)
            .is_some_and(|value| {
                roots.iter().all(|root| {
                    super::trusted_location::trusted_library_search_path(
                        value,
                        Path::new(home),
                        Path::new(root),
                    )
                })
            })
}

#[cfg(all(test, unix))]
mod tests {
    use super::{inert_npm_config_name, GuardExecutionEnvironmentV1};
    use std::path::{Path, PathBuf};

    fn environment(names: &[&str], loader: Option<&Path>) -> GuardExecutionEnvironmentV1 {
        GuardExecutionEnvironmentV1 {
            path: "/usr/bin:/bin".into(),
            environment_names: names.iter().map(|name| (*name).to_owned()).collect(),
            environment_digest: "0".repeat(64),
            home: None,
            git_pager_disabled: false,
            pager_disabled: false,
            xdg_config_home: None,
            git_config_no_system: false,
            library_search_paths: loader
                .map(|path| ("LD_LIBRARY_PATH".to_owned(), path.display().to_string()))
                .into_iter()
                .collect(),
        }
    }

    fn inert(home: &Path, cwd: &Path, environment: &GuardExecutionEnvironmentV1) -> bool {
        super::super::PathContext::for_session(home.to_str(), cwd.to_str(), Some(environment))
            .npm_config_inert
    }

    #[test]
    fn only_cache_and_output_keys_are_inert() {
        for name in [
            "npm_config_cache",
            "NPM_CONFIG_LOGLEVEL",
            "npm_config_update-notifier",
        ] {
            assert!(inert_npm_config_name(name), "{name}");
        }
        for name in [
            "npm_config_registry",
            "npm_config_userconfig",
            "npm_config_globalconfig",
            "npm_config_script_shell",
            "npm_config_node_options",
            "npm_config_",
            "NODE_OPTIONS",
            "cache",
        ] {
            assert!(!inert_npm_config_name(name), "{name}");
        }
    }

    #[test]
    fn a_home_loader_path_keeps_npm_configuration_inert_and_a_project_one_does_not() {
        let root: PathBuf = std::fs::canonicalize("/tmp")
            .unwrap()
            .join(format!("guard-npm-environment-{}", std::process::id()));
        let home = root.join("home");
        let library = home.join(".local").join("lib");
        let project = home.join("app-portal");
        let planted = project.join("lib");
        for directory in [&library, &planted] {
            std::fs::create_dir_all(directory).unwrap();
        }
        let names = ["LD_LIBRARY_PATH", "npm_config_cache"];
        let home_loader = inert(&home, &project, &environment(&names, Some(&library)));
        let project_loader = inert(&home, &project, &environment(&names, Some(&planted)));
        let unstamped = inert(&home, &project, &environment(&["LD_LIBRARY_PATH"], None));
        let preload = inert(&home, &project, &environment(&["LD_PRELOAD"], None));
        let registry = inert(
            &home,
            &project,
            &environment(&["npm_config_registry"], None),
        );
        let _ = std::fs::remove_dir_all(&root);
        assert!(home_loader);
        assert!(!project_loader);
        assert!(!unstamped);
        assert!(!preload);
        assert!(!registry);
    }
}
