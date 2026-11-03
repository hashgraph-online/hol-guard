use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::dispatch;
use super::lookup::{system_only_path, version_key};
use crate::runner_authority_op::ERR_INVALID;

const COMMAND: &str = "guardtestcli-user-lookup";
const LAUNCHD_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

fn home() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = std::fs::canonicalize(directory.path()).expect("canonical tempdir");
    (directory, home)
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn install(directory: &Path, mode: u32) -> PathBuf {
    std::fs::create_dir_all(directory).expect("mkdir");
    chmod(directory, 0o755);
    let executable = directory.join(COMMAND);
    std::fs::write(&executable, "#!/bin/sh\nexit 0\n").expect("write");
    chmod(&executable, mode);
    executable
}

fn spelled(path: &Path) -> String {
    path.to_str().expect("utf-8 path").to_owned()
}

fn find(home: &Path, path: &str, extra: &[&Path]) -> Value {
    let extra: Vec<String> = extra.iter().map(|directory| spelled(directory)).collect();
    let request = json!({"command": COMMAND, "home": spelled(home), "path": path, "extra": extra});
    dispatch(&request).expect("lookup answer")["path"].clone()
}

#[test]
fn a_bare_launchd_path_finds_a_cli_in_a_user_install_directory() {
    let (_directory, home) = home();
    let executable = install(&home.join(".bun/bin"), 0o755);
    assert_eq!(find(&home, LAUNCHD_PATH, &[]), json!(spelled(&executable)));
    // The tool's own installer directory is a user install directory too.
    let (_other, own) = self::home();
    let executable = install(&own.join(format!(".{COMMAND}/bin")), 0o755);
    assert_eq!(find(&own, LAUNCHD_PATH, &[]), json!(spelled(&executable)));
}

#[test]
fn the_newest_nvm_node_release_wins() {
    let (_directory, home) = home();
    let versions = home.join(".nvm/versions/node");
    install(&versions.join("v9.11.2/bin"), 0o755);
    let newest = install(&versions.join("v25.2.1/bin"), 0o755);
    install(&versions.join("system/bin"), 0o755);
    assert_eq!(find(&home, LAUNCHD_PATH, &[]), json!(spelled(&newest)));
}

#[test]
fn version_keys_order_numbers_above_other_parts() {
    assert!(version_key("v25.2.1") > version_key("v9.11.2"));
    assert!(version_key("v10.0.0") > version_key("v9.99.99"));
    assert_eq!(version_key("v010.1"), version_key("10.1"));
    assert!(version_key("v1.0.0") > version_key("v1.0.x"));
    assert!(version_key("v1.0.0") > version_key("v1.0"));
    assert!(version_key("0") > version_key("system"));
    let huge = format!("1{}", "0".repeat(60));
    assert!(version_key(&huge) > version_key("99"));
}

#[test]
fn only_a_bare_system_path_widens_the_search() {
    assert!(system_only_path(Some(LAUNCHD_PATH)));
    assert!(system_only_path(Some("/usr/bin/:/bin//")));
    assert!(system_only_path(Some("::/usr/bin::")));
    for path in [
        None,
        Some(""),
        Some(":"),
        Some(":::"),
        Some("/usr/bin:/opt/x"),
    ] {
        assert!(!system_only_path(path), "{path:?}");
    }
    let (_directory, home) = home();
    install(&home.join(".bun/bin"), 0o755);
    let terminal = format!("{}:{LAUNCHD_PATH}", spelled(&home.join("empty")));
    for path in [terminal.as_str(), "", ":::"] {
        assert_eq!(find(&home, path, &[]), Value::Null, "{path}");
    }
}

#[test]
fn installer_directories_are_searched_under_any_path_with_the_same_checks() {
    let (_directory, home) = home();
    install(&home.join(".bun/bin"), 0o755);
    let installer = home.join(".guardtestcli-code/bin");
    let executable = install(&installer, 0o755);
    let terminal = format!("{}:{LAUNCHD_PATH}", spelled(&home.join("empty")));
    assert_eq!(find(&home, &terminal, &[]), Value::Null);
    assert_eq!(
        find(&home, &terminal, &[&installer]),
        json!(spelled(&executable))
    );
    chmod(&installer, 0o777);
    assert_eq!(find(&home, LAUNCHD_PATH, &[&installer]), Value::Null);
    // A relative directory would resolve against the resident's cwd.
    assert_eq!(
        find(&home, &terminal, &[Path::new(".guardtestcli-code/bin")]),
        Value::Null
    );
}

#[test]
fn writable_directories_and_non_executables_are_ignored() {
    let (_directory, home) = home();
    let executable = install(&home.join(".bun/bin"), 0o777);
    // A world-writable entrypoint in a private directory is still found.
    assert_eq!(find(&home, LAUNCHD_PATH, &[]), json!(spelled(&executable)));
    chmod(&home.join(".bun/bin"), 0o757);
    assert_eq!(find(&home, LAUNCHD_PATH, &[]), Value::Null);

    let (_other, home) = self::home();
    install(&home.join(".local/bin"), 0o644);
    assert_eq!(find(&home, LAUNCHD_PATH, &[]), Value::Null);
}

#[test]
fn links_are_judged_by_where_they_lead() {
    let (_directory, home) = home();
    let shared = home.join("shared");
    let target = install(&shared, 0o755);
    chmod(&shared, 0o777);
    std::fs::create_dir_all(home.join(".bun/bin")).expect("mkdir");
    symlink(&target, home.join(".bun/bin").join(COMMAND)).expect("symlink");
    assert_eq!(find(&home, LAUNCHD_PATH, &[]), Value::Null);

    let (_other, home) = self::home();
    let directory = home.join(".bun/bin");
    std::fs::create_dir_all(&directory).expect("mkdir");
    symlink(directory.join(COMMAND), directory.join(COMMAND)).expect("loop");
    assert_eq!(find(&home, LAUNCHD_PATH, &[]), Value::Null);
}

#[test]
fn a_command_with_a_separator_or_a_malformed_request_is_refused() {
    let (_directory, home) = home();
    install(&home.join(".bun/bin"), 0o755);
    let request = json!({"command": format!("../{COMMAND}"), "home": spelled(&home), "path": LAUNCHD_PATH, "extra": []});
    assert_eq!(dispatch(&request).expect("answer")["path"], Value::Null);
    for request in [
        json!({"home": "/h", "path": null, "extra": []}),
        json!({"command": "x", "home": "/h", "path": 1, "extra": []}),
        json!({"command": "x", "home": "/h", "path": null}),
        json!({"command": "x", "home": "/h", "path": null, "extra": [1]}),
        json!({"command": "x", "home": "/h", "path": null, "extra": vec!["/x"; 65]}),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
