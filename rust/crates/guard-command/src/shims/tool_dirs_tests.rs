//! Package-manager discovery when the daemon's PATH is the launcher's PATH.
//!
//! A desktop or IDE launcher hands a long-lived daemon the bare system PATH, so
//! managers installed under the user's home (nvm, cargo, bun, uv, pnpm) look
//! absent although the user's shell reaches them. The daemon marks its own
//! requests with `HOL_GUARD_SHIM_TOOL_DIRS=1`; every other caller keeps
//! searching exactly the PATH it passed.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::{get_path_order_status, package_shim_status, ShimContext, ShimFacts};

const MARKER: &str = "HOL_GUARD_SHIM_TOOL_DIRS";

struct Machine {
    _root: tempfile::TempDir,
    home: PathBuf,
    guard_home: PathBuf,
    launcher_bin: PathBuf,
}

fn machine() -> Machine {
    let root = tempfile::tempdir().expect("tempdir");
    let home = root.path().join("home");
    let launcher_bin = root.path().join("launcher-bin");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&launcher_bin).expect("launcher bin");
    Machine {
        guard_home: root.path().join("guard"),
        _root: root,
        home,
        launcher_bin,
    }
}

fn install_tool(directory: &Path, name: &str) -> PathBuf {
    fs::create_dir_all(directory).expect("tool dir");
    let path = directory.join(name);
    fs::write(&path, "#!/bin/sh\nexit 0\n").expect("tool");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

fn context(machine: &Machine, marker: Option<&str>) -> ShimContext {
    let mut environ = BTreeMap::from([(
        "PATH".to_owned(),
        machine.launcher_bin.to_string_lossy().into_owned(),
    )]);
    if let Some(value) = marker {
        environ.insert(MARKER.to_owned(), value.to_owned());
    }
    let home = machine.home.to_string_lossy().into_owned();
    ShimContext::new(
        &machine.guard_home.to_string_lossy(),
        Some(&home),
        None,
        ShimFacts {
            environ,
            home: home.clone(),
            cwd: home.clone(),
            executable: "/usr/bin/python3".to_owned(),
            frozen: false,
            frozen_cli: String::new(),
            trusted_frozen_cli_paths: Vec::new(),
            python_version: (3, 12),
            import_root: "/opt/guard/src".to_owned(),
            argv0: None,
            windows: false,
            sqlite_connect_timeout_seconds: 30.0,
            now: "2026-01-01T00:00:00+00:00".to_owned(),
            shim_dir_transient: None,
        },
    )
}

fn detected(context: &ShimContext, path_env: Option<&str>) -> Vec<String> {
    let status = package_shim_status(context, path_env).expect("status");
    strings(&status, "detected_managers")
}

fn strings(status: &Map<String, Value>, key: &str) -> Vec<String> {
    status
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn install_home_tools(machine: &Machine) {
    install_tool(&machine.home.join(".cargo/bin"), "cargo");
    install_tool(&machine.home.join(".bun/bin"), "bun");
    install_tool(&machine.home.join(".bun/bin"), "bunx");
    install_tool(&machine.home.join(".local/bin"), "uv");
    install_tool(&machine.home.join(".local/share/pnpm"), "pnpm");
    install_tool(&machine.home.join(".yarn/bin"), "yarn");
    install_tool(&machine.home.join(".nvm/versions/node/v22.4.0/bin"), "npm");
}

#[test]
fn a_launcher_path_without_the_marker_searches_only_that_path() {
    let machine = machine();
    install_home_tools(&machine);
    assert_eq!(
        detected(&context(&machine, None), None),
        Vec::<String>::new()
    );
}

#[test]
fn only_the_exact_marker_value_turns_discovery_on() {
    let machine = machine();
    install_home_tools(&machine);
    for value in ["0", "", "true", "yes"] {
        assert_eq!(
            detected(&context(&machine, Some(value)), None),
            Vec::<String>::new(),
            "marker value {value:?}"
        );
    }
}

#[test]
fn the_marker_finds_managers_installed_under_the_home_directory() {
    let machine = machine();
    install_home_tools(&machine);
    let found = detected(&context(&machine, Some("1")), None);
    for manager in ["bun", "bunx", "cargo", "npm", "pnpm", "uv", "yarn"] {
        assert!(
            found.contains(&manager.to_owned()),
            "{manager} in {found:?}"
        );
    }
}

#[test]
fn every_nvm_node_version_counts() {
    let machine = machine();
    install_tool(&machine.home.join(".nvm/versions/node/v18.20.0/bin"), "npx");
    install_tool(&machine.home.join(".nvm/versions/node/v22.4.0/bin"), "npm");
    let found = detected(&context(&machine, Some("1")), None);
    assert!(found.contains(&"npm".to_owned()), "{found:?}");
    assert!(found.contains(&"npx".to_owned()), "{found:?}");
}

#[test]
fn the_newest_node_versions_are_searched_when_there_are_many() {
    let machine = machine();
    for major in 1..=12 {
        install_tool(
            &machine
                .home
                .join(format!(".nvm/versions/node/v{major}.0.0/bin")),
            &format!("tool{major}"),
        );
    }
    let path = context(&machine, Some("1")).search_path(None);
    assert!(path.contains("/v12.0.0/bin"), "{path}");
    assert!(path.contains("/v9.0.0/bin"), "{path}");
    assert!(!path.contains("/v4.0.0/bin"), "{path}");
}

#[test]
fn an_explicit_path_is_searched_alone() {
    let machine = machine();
    install_home_tools(&machine);
    let explicit = machine.launcher_bin.to_string_lossy().into_owned();
    assert_eq!(
        detected(&context(&machine, Some("1")), Some(&explicit)),
        Vec::<String>::new()
    );
}

#[test]
fn the_launcher_path_wins_over_a_discovered_directory() {
    let machine = machine();
    let launcher_cargo = install_tool(&machine.launcher_bin, "cargo");
    install_tool(&machine.home.join(".cargo/bin"), "cargo");
    let order =
        get_path_order_status(&context(&machine, Some("1")), "cargo", None).expect("path order");
    assert_eq!(
        order.get("real_binary_path").and_then(Value::as_str),
        launcher_cargo.to_str()
    );
}

#[test]
fn the_real_binary_is_reported_from_the_discovered_directory() {
    let machine = machine();
    let bun = install_tool(&machine.home.join(".bun/bin"), "bun");
    let order =
        get_path_order_status(&context(&machine, Some("1")), "bun", None).expect("path order");
    assert_eq!(order.get("real_binary_found"), Some(&Value::Bool(true)));
    assert_eq!(
        order.get("real_binary_path").and_then(Value::as_str),
        bun.to_str()
    );
    let without = get_path_order_status(&context(&machine, None), "bun", None).expect("path order");
    assert_eq!(without.get("real_binary_found"), Some(&Value::Bool(false)));
}

#[test]
fn widening_the_search_does_not_change_whether_the_shim_leads() {
    let machine = machine();
    let shim_dir = machine.guard_home.join("package-shims").join("bin");
    fs::create_dir_all(&shim_dir).expect("shim dir");
    let launcher_path = format!(
        "{}:{}",
        shim_dir.to_string_lossy(),
        machine.launcher_bin.to_string_lossy()
    );
    install_tool(&machine.home.join(".bun/bin"), "bun");
    let before = path_order(&machine, None, &launcher_path);
    let after = path_order(&machine, Some("1"), &launcher_path);
    assert_eq!(after.get("real_binary_found"), Some(&Value::Bool(true)));
    assert_eq!(before.get("real_binary_found"), Some(&Value::Bool(false)));
    for key in ["shim_precedes_real", "path_broken"] {
        assert_eq!(after.get(key), before.get(key), "{key}");
    }
}

fn path_order(machine: &Machine, marker: Option<&str>, path: &str) -> Map<String, Value> {
    let mut context = context(machine, marker);
    context
        .facts
        .environ
        .insert("PATH".to_owned(), path.to_owned());
    get_path_order_status(&context, "bun", None).expect("path order")
}
