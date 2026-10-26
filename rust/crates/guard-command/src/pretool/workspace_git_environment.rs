//! The Git configuration variables a later host Git will see, and the global
//! configuration files they select for the workspace sandbox admission.
use guard_contracts::GuardExecutionEnvironmentV1;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The Git configuration variables a later host Git will see, by name. A
/// name whose value did not travel with the request is `None`.
pub(crate) type GitVariables = BTreeMap<String, Option<String>>;

/// The variables a stamped session environment carries, or the runtime's own
/// without one. Only the XDG value travels in a stamp; `None` for a malformed
/// stamp.
pub(crate) fn session_git_variables(
    environment: Option<&GuardExecutionEnvironmentV1>,
) -> Option<GitVariables> {
    let Some(environment) = environment else {
        return Some(
            std::env::vars_os()
                .filter_map(|(name, value)| {
                    let name = name.into_string().ok()?;
                    git_variable(&name).then(|| (name, value.into_string().ok()))
                })
                .collect(),
        );
    };
    if !environment.has_valid_shape() {
        return None;
    }
    let mut variables: GitVariables = environment
        .environment_names
        .iter()
        .filter(|name| git_variable(name))
        .map(|name| (name.clone(), None))
        .collect();
    if let Some(value) = &environment.xdg_config_home {
        variables.insert("XDG_CONFIG_HOME".into(), Some(value.clone()));
    }
    Some(variables)
}

pub(crate) fn git_variable(name: &str) -> bool {
    name.starts_with("GIT_CONFIG") || name == "XDG_CONFIG_HOME"
}

/// Configuration files host Git reads besides the repository's own, before
/// includes. A relative `core.hooksPath` in any of them resolves against each
/// work tree. `None` when a variable names configuration this cannot read.
pub(super) fn global_config_paths(
    home: Option<&Path>,
    variables: &GitVariables,
) -> Option<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = [
        "/etc/gitconfig",
        "/opt/homebrew/etc/gitconfig",
        "/usr/local/etc/gitconfig",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    if let Some(home) = home {
        paths.push(home.join(".gitconfig"));
        paths.push(home.join(".config/git/config"));
    }
    for (name, value) in variables {
        if name == "GIT_CONFIG_NOSYSTEM" {
            continue;
        }
        // A value that did not travel, and command-line style entries
        // (`GIT_CONFIG_COUNT`, `_KEY_n`, `_PARAMETERS`), stay at review.
        let value = value.as_deref()?;
        if value.is_empty() {
            continue;
        }
        match name.as_str() {
            "GIT_CONFIG_GLOBAL" | "GIT_CONFIG_SYSTEM" => paths.push(PathBuf::from(value)),
            "XDG_CONFIG_HOME" => paths.push(Path::new(value).join("git/config")),
            _ => return None,
        }
    }
    Some(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp(names: &[&str], xdg: Option<&str>) -> GuardExecutionEnvironmentV1 {
        GuardExecutionEnvironmentV1 {
            path: "/usr/bin:/bin".into(),
            environment_names: names.iter().map(|name| (*name).to_owned()).collect(),
            environment_digest: "0".repeat(64),
            home: None,
            git_pager_disabled: false,
            pager_disabled: false,
            xdg_config_home: xdg.map(str::to_owned),
            git_config_no_system: false,
            library_search_paths: Default::default(),
        }
    }

    fn paths_for(stamp: &GuardExecutionEnvironmentV1) -> Option<Vec<PathBuf>> {
        global_config_paths(None, &session_git_variables(Some(stamp))?)
    }

    #[test]
    fn the_session_xdg_value_is_read_instead_of_the_runtime_one() {
        let paths = paths_for(&stamp(&["PATH", "XDG_CONFIG_HOME"], Some("/w/proj/.cfg"))).unwrap();
        assert!(paths.contains(&PathBuf::from("/w/proj/.cfg/git/config")));
        let paths = paths_for(&stamp(&["PATH", "GIT_CONFIG_NOSYSTEM"], None)).unwrap();
        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn git_configuration_whose_value_did_not_travel_stays_at_review() {
        for names in [
            &["GIT_CONFIG_GLOBAL"][..],
            &["GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0"],
            &["XDG_CONFIG_HOME"],
        ] {
            assert_eq!(paths_for(&stamp(names, None)), None, "{names:?}");
        }
        let mut malformed = stamp(&[], None);
        malformed.environment_digest = "x".into();
        assert_eq!(session_git_variables(Some(&malformed)), None);
    }

    #[test]
    fn exported_values_select_files_and_inline_entries_stay_at_review() {
        let values = |pairs: &[(&str, &str)]| -> GitVariables {
            pairs
                .iter()
                .map(|(name, value)| ((*name).to_owned(), Some((*value).to_owned())))
                .collect()
        };
        let paths = global_config_paths(
            None,
            &values(&[("GIT_CONFIG_GLOBAL", "/w/proj/g"), ("XDG_CONFIG_HOME", "")]),
        )
        .unwrap();
        assert_eq!(paths.last(), Some(&PathBuf::from("/w/proj/g")));
        assert_eq!(
            global_config_paths(None, &values(&[("GIT_CONFIG_PARAMETERS", "'a.b'='c'")])),
            None
        );
    }
}
