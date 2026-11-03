//! Whether npm's configuration adds a package to an `npx` launch: how npm
//! names its settings, which `.npmrc` lines count, and which files are read.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::*;

fn tokens(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

/// A project under its own home folder, and an environment naming that home.
fn project() -> (TempDir, PathBuf, BTreeMap<String, String>) {
    let dir = TempDir::new().unwrap();
    let home = dir.path().join("home");
    let project = home.join("src").join("demo");
    fs::create_dir_all(&project).unwrap();
    let environment = BTreeMap::from([("HOME".to_owned(), home.to_string_lossy().into_owned())]);
    (dir, project, environment)
}

fn npmrc(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join(".npmrc");
    fs::write(&path, body).unwrap();
    path
}

fn adds(environment: &BTreeMap<String, String>, cwd: &Path) -> bool {
    let home = environment.get("HOME").map(Path::new);
    npm_config_adds_package(environment, cwd, home)
}

#[test]
fn environment_names_map_to_npm_settings_the_way_npm_maps_them() {
    for (name, setting) in [
        ("npm_config_package", Some("package")),
        ("NPM_CONFIG_PACKAGE", Some("package")),
        ("Npm_Config_UserConfig", Some("userconfig")),
        ("npm_config_update_notifier", Some("update-notifier")),
        ("npm_config__private", Some("_private")),
        ("npm_config_//registry.npmjs.org/:_authToken", None),
        ("npm_config_", None),
        ("PACKAGE", None),
        ("npm_configpackage", None),
    ] {
        assert_eq!(npm_setting_name(name).as_deref(), setting, "{name}");
    }
}

#[test]
fn a_command_that_assigns_a_package_setting_is_flagged() {
    for words in [
        &["npm_config_package=left-pad", "npx", "tsx"][..],
        &["env", "NPM_CONFIG_PACKAGE=left-pad", "npx", "tsx"],
        &[
            "env",
            "-i",
            "npm_config_userconfig=/elsewhere/npmrc",
            "npx",
            "tsx",
        ],
        &["export", "npm_config_globalconfig=/elsewhere/npmrc"],
        &["npm_config_package=", "npx", "tsx"],
    ] {
        assert!(assigns_npm_package_setting(&tokens(words)), "{words:?}");
    }
    for words in [
        &["npx", "tsx", "scripts/run.ts"][..],
        &[
            "npm_config_registry=https://registry.npmjs.org/",
            "npx",
            "tsx",
        ],
        &["env", "FOO=1", "npx", "tsx"],
        &["npx", "tsx", "--define=package=left-pad"],
    ] {
        assert!(!assigns_npm_package_setting(&tokens(words)), "{words:?}");
    }
}

#[test]
fn an_npmrc_that_names_a_package_setting_is_flagged() {
    let dir = TempDir::new().unwrap();
    for body in [
        "package=left-pad\n",
        "  package = left-pad\n",
        "package[]=left-pad\n",
        "\"package\" = left-pad\n",
        "PACKAGE=left-pad\n",
        "\u{feff}package=left-pad\n",
        "registry=https://registry.npmjs.org/\r\npackage=left-pad\r\n",
        "registry=https://registry.npmjs.org/\rpackage=left-pad",
        "[section]\npackage=left-pad\n",
        "package\n",
        // npm expands ${VAR} inside setting names.
        "${SETTING}=left-pad\n",
        "userconfig=./other.npmrc\n",
        "globalconfig=/elsewhere/npmrc\n",
    ] {
        assert!(npmrc_sets_package(&npmrc(dir.path(), body)), "{body:?}");
    }
}

#[test]
fn an_npmrc_without_a_package_setting_is_not_flagged() {
    let dir = TempDir::new().unwrap();
    for body in [
        "",
        "registry=https://registry.npmjs.org/\nsave-exact=true\n",
        "; package=left-pad\n# package=left-pad\n",
        "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n",
        "@scope:registry=https://npm.example.test/\n",
        "packages=left-pad\npackage-lock=false\n",
    ] {
        assert!(!npmrc_sets_package(&npmrc(dir.path(), body)), "{body:?}");
    }
}

#[test]
fn npmrc_files_that_cannot_be_read_in_full_keep_the_review() {
    let dir = TempDir::new().unwrap();
    assert!(!npmrc_sets_package(&dir.path().join(".npmrc")));
    assert!(!npmrc_sets_package(
        &dir.path().join("missing").join(".npmrc")
    ));

    // Not a regular file: never opened, so a FIFO could not stall the parser.
    fs::create_dir(dir.path().join(".npmrc")).unwrap();
    assert!(npmrc_sets_package(&dir.path().join(".npmrc")));

    let oversized = TempDir::new().unwrap();
    let body = "; filler\n".repeat(usize::try_from(NPMRC_READ_LIMIT).unwrap() / 9 + 1);
    assert!(npmrc_sets_package(&npmrc(oversized.path(), &body)));
}

#[test]
fn the_package_setting_in_the_environment_adds_a_package() {
    let (_dir, project, environment) = project();
    assert!(!adds(&environment, &project));
    for name in ["npm_config_package", "NPM_CONFIG_PACKAGE"] {
        let mut named = environment.clone();
        named.insert(name.to_owned(), "left-pad".to_owned());
        assert!(adds(&named, &project), "{name}");
    }
    // npm skips an empty value.
    let mut empty = environment.clone();
    empty.insert("npm_config_package".to_owned(), String::new());
    assert!(!adds(&empty, &project));
}

#[test]
fn an_npmrc_in_the_project_or_any_folder_above_it_adds_a_package() {
    for depth in 0..3 {
        let (_dir, project, environment) = project();
        let folder = project.ancestors().nth(depth).unwrap();
        npmrc(folder, "package=left-pad\n");
        assert!(adds(&environment, &project), "{depth}");
    }
}

#[test]
fn the_user_config_is_home_unless_the_environment_names_another_file() {
    let (dir, _project, environment) = project();
    let outside = dir.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    let home = PathBuf::from(&environment["HOME"]);
    npmrc(&home, "package=left-pad\n");
    assert!(adds(&environment, &outside));

    let other = dir.path().join("other.npmrc");
    fs::write(&other, "registry=https://registry.npmjs.org/\n").unwrap();
    let mut redirected = environment.clone();
    redirected.insert(
        "npm_config_userconfig".to_owned(),
        other.to_string_lossy().into_owned(),
    );
    assert!(!adds(&redirected, &outside));
    fs::write(&other, "package=left-pad\n").unwrap();
    assert!(adds(&redirected, &outside));

    // `~/` is the home folder; a path npm would expand first keeps the review.
    redirected.insert("npm_config_userconfig".to_owned(), "~/.npmrc".to_owned());
    assert!(adds(&redirected, &outside));
    redirected.insert(
        "npm_config_userconfig".to_owned(),
        "${CONFIG_DIR}/npmrc".to_owned(),
    );
    assert!(adds(&redirected, &outside));
}

#[test]
fn a_global_config_named_by_the_environment_is_read() {
    let (dir, project, mut environment) = project();
    let global = dir.path().join("prefix").join("etc");
    fs::create_dir_all(&global).unwrap();
    let path = npmrc(&global, "package=left-pad\n");
    environment.insert(
        "NPM_CONFIG_GLOBALCONFIG".to_owned(),
        path.to_string_lossy().into_owned(),
    );
    assert!(adds(&environment, &project));
}

#[test]
fn ordinary_npm_settings_add_nothing() {
    let (_dir, project, mut environment) = project();
    npmrc(
        &project,
        "registry=https://registry.npmjs.org/\nsave-exact=true\n",
    );
    npmrc(Path::new(&environment["HOME"]), "fund=false\n");
    environment.insert("npm_config_fund".to_owned(), "false".to_owned());
    assert!(!adds(&environment, &project));
}

#[test]
fn a_named_package_setting_is_the_spec_npm_installs() {
    let (_dir, project, environment) = project();
    npmrc(&project, "package[]=left-pad\npackage[]=cowsay\n");

    assert_eq!(
        npm_configured_exec_packages(
            &environment,
            &project,
            Some(Path::new(&environment["HOME"]))
        ),
        NpmConfiguredPackages::Named(vec!["left-pad".to_owned(), "cowsay".to_owned()])
    );
}

#[test]
fn an_environment_package_wins_over_a_file() {
    let (_dir, project, mut environment) = project();
    npmrc(&project, "package=cowsay\n");
    environment.insert("npm_config_package".to_owned(), "left-pad".to_owned());

    assert_eq!(
        npm_configured_exec_packages(
            &environment,
            &project,
            Some(Path::new(&environment["HOME"]))
        ),
        NpmConfiguredPackages::Named(vec!["left-pad".to_owned()])
    );
}

#[test]
fn an_env_assignment_on_the_command_names_the_package() {
    let (dir, project, environment) = project();
    let home = PathBuf::from(&environment["HOME"]);
    let intent = parse_package_intent(
        "env npm_config_package=left-pad npx tsx script.ts",
        Some(&project),
        Some(&home),
        None,
        Some(&environment),
    )
    .expect("npx intent");

    assert_eq!(intent.targets[0].package_name.as_deref(), Some("left-pad"));
    assert!(intent
        .targets
        .iter()
        .all(|target| target.source_invalid_reason.is_none()));
    let _ = dir;
}

#[test]
fn a_nested_env_wrapper_names_the_inner_package() {
    let (dir, project, environment) = project();
    let home = PathBuf::from(&environment["HOME"]);
    let intent = parse_package_intent(
        "env FOO=1 env npm_config_package=left-pad npx tsx script.ts",
        Some(&project),
        Some(&home),
        None,
        Some(&environment),
    )
    .expect("npx intent");

    assert_eq!(intent.targets[0].package_name.as_deref(), Some("left-pad"));
    assert!(intent
        .targets
        .iter()
        .all(|target| target.source_invalid_reason.is_none()));
    let _ = dir;
}

#[test]
fn an_inner_env_names_the_package_after_the_environment_was_cleared() {
    let (dir, project, environment) = project();
    let home = PathBuf::from(&environment["HOME"]);
    let intent = parse_package_intent(
        "env -i env npm_config_package=left-pad npx tsx script.ts",
        Some(&project),
        Some(&home),
        None,
        Some(&environment),
    )
    .expect("npx intent");

    assert_eq!(intent.targets[0].package_name.as_deref(), Some("left-pad"));
    assert!(intent
        .targets
        .iter()
        .all(|target| target.source_invalid_reason.is_none()));
    let _ = dir;
}

#[test]
fn an_inner_env_that_clears_the_environment_leaves_the_package_unnamed() {
    let (dir, project, environment) = project();
    let home = PathBuf::from(&environment["HOME"]);
    let intent = parse_package_intent(
        "env npm_config_package=left-pad env -i npx tsx script.ts",
        Some(&project),
        Some(&home),
        None,
        Some(&environment),
    )
    .expect("npx intent");

    assert_eq!(
        intent.targets[0].source_invalid_reason.as_deref(),
        Some("npm_config_package_unidentified")
    );
    let _ = dir;
}

#[test]
fn a_userconfig_path_expands_before_the_file_is_read() {
    let (dir, _project, mut environment) = project();
    let outside = dir.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    let folder = dir.path().join("cfg");
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join("npmrc"), "package=left-pad\n").unwrap();
    environment.insert("CFG_DIR".to_owned(), folder.to_string_lossy().into_owned());
    environment.insert(
        "npm_config_userconfig".to_owned(),
        "${CFG_DIR}/npmrc".to_owned(),
    );

    assert_eq!(
        npm_configured_exec_packages(
            &environment,
            &outside,
            Some(Path::new(&environment["HOME"]))
        ),
        NpmConfiguredPackages::Named(vec!["left-pad".to_owned()])
    );
}

#[test]
fn an_unresolved_userconfig_path_leaves_the_package_unnamed() {
    let (_dir, project, mut environment) = project();
    environment.insert(
        "npm_config_userconfig".to_owned(),
        "${CFG_DIR}/npmrc".to_owned(),
    );

    assert_eq!(
        npm_configured_exec_packages(
            &environment,
            &project,
            Some(Path::new(&environment["HOME"]))
        ),
        NpmConfiguredPackages::Unnamed
    );
}

#[test]
fn a_command_line_package_replaces_the_configured_package() {
    let (dir, project, environment) = project();
    npmrc(&project, "package=left-pad\n");
    let home = PathBuf::from(&environment["HOME"]);
    let intent = parse_package_intent(
        "npx --package=evil tsx script.ts",
        Some(&project),
        Some(&home),
        None,
        Some(&environment),
    )
    .expect("npx intent");

    assert_eq!(
        intent
            .targets
            .iter()
            .filter_map(|target| target.package_name.as_deref())
            .collect::<Vec<_>>(),
        vec!["evil"]
    );
    let _ = dir;
}

#[test]
fn a_short_package_option_replaces_the_configured_package() {
    let (dir, project, environment) = project();
    npmrc(&project, "package=left-pad\n");
    let home = PathBuf::from(&environment["HOME"]);
    let intent = parse_package_intent(
        "npx -p evil tsx script.ts",
        Some(&project),
        Some(&home),
        None,
        Some(&environment),
    )
    .expect("npx intent");

    assert_eq!(intent.targets[0].package_name.as_deref(), Some("evil"));
    let _ = dir;
}

#[test]
fn a_package_flag_after_the_executable_does_not_replace_npm_config() {
    let (dir, project, environment) = project();
    npmrc(&project, "package=left-pad\n");
    let home = PathBuf::from(&environment["HOME"]);
    let intent = parse_package_intent(
        "npx tsx --package=evil script.ts",
        Some(&project),
        Some(&home),
        None,
        Some(&environment),
    )
    .expect("npx intent");

    assert_eq!(intent.targets[0].package_name.as_deref(), Some("left-pad"));
    let _ = dir;
}

#[test]
fn an_unreadable_npmrc_does_not_block_a_command_line_package() {
    let (dir, project, environment) = project();
    fs::create_dir(project.join(".npmrc")).unwrap();
    let home = PathBuf::from(&environment["HOME"]);
    let intent = parse_package_intent(
        "npx --package=evil tsx script.ts",
        Some(&project),
        Some(&home),
        None,
        Some(&environment),
    )
    .expect("npx intent");

    assert_eq!(intent.targets[0].package_name.as_deref(), Some("evil"));
    assert!(intent
        .targets
        .iter()
        .all(|target| target.source_invalid_reason.is_none()));
    let _ = dir;
}

#[test]
fn a_directory_npmrc_leaves_the_package_unnamed() {
    let (_dir, project, environment) = project();
    fs::create_dir(project.join(".npmrc")).unwrap();

    assert_eq!(
        npm_configured_exec_packages(
            &environment,
            &project,
            Some(Path::new(&environment["HOME"]))
        ),
        NpmConfiguredPackages::Unnamed
    );
}

#[test]
fn an_unknown_home_or_launch_folder_keeps_the_review() {
    let (_dir, project, _environment) = project();
    assert!(npm_config_adds_package(&BTreeMap::new(), &project, None));
    assert!(npm_config_adds_package(
        &BTreeMap::new(),
        Path::new("relative/project"),
        Some(&project)
    ));
}
