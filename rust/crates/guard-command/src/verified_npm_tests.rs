//! Oracle tests for the npm-proving port. Each case mirrors a branch of the
//! Python `verified_npm_version` it replaces.

use std::fs;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;

use serde_json::json;
#[cfg(unix)]
use serde_json::Value;

use super::*;

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "hol-guard-verified-npm-{}-{}-{:?}",
            name,
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("fixture root must be creatable");
        Self { root }
    }

    fn workspace(&self) -> PathBuf {
        let workspace = self.root.join("workspace");
        fs::create_dir_all(&workspace).expect("workspace must be creatable");
        workspace
    }

    /// A standard npm layout: `<prefix>/bin/npm` links into `lib/node_modules`.
    #[cfg(unix)]
    fn npm_prefix(&self, version: &str) -> PathBuf {
        let prefix = self.root.join("prefix");
        let bin = prefix.join("bin");
        let package = prefix.join("lib").join("node_modules").join("npm");
        fs::create_dir_all(package.join("bin")).expect("npm package must be creatable");
        fs::create_dir_all(&bin).expect("bin must be creatable");
        write_executable(&package.join("bin").join("npm-cli.js"), "// npm");
        write_executable(&bin.join("npm"), "#!/bin/sh\n");
        write_executable(&bin.join("node"), "#!/bin/sh\n");
        fs::write(
            package.join("package.json"),
            json!({"name": "npm", "version": version}).to_string(),
        )
        .expect("manifest must be writable");
        link(&package.join("bin").join("npm-cli.js"), &bin.join("npm"));
        prefix
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
fn write_executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, body).expect("file must be writable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("mode must be settable");
}

#[cfg(unix)]
fn link(target: &Path, at: &Path) {
    let _ = fs::remove_file(at);
    std::os::unix::fs::symlink(target, at).expect("symlink must be creatable");
}

#[cfg(unix)]
fn environment(prefix: &Path, home: &Path, extra_names: &[&str]) -> ExecutionEnvironment {
    let mut names: Vec<Value> = vec![json!("PATH"), json!("HOME")];
    names.extend(extra_names.iter().map(|name| json!(name)));
    ExecutionEnvironment::from_value(Some(&json!({
        "environment_names": names,
        "path": prefix.join("bin").to_string_lossy(),
        "home": home.to_string_lossy(),
    })))
}

#[cfg(unix)]
#[test]
fn a_standard_npm_on_an_absolute_path_proves_its_version() {
    let fixture = Fixture::new("standard");
    let prefix = fixture.npm_prefix("11.9.0");
    let workspace = fixture.workspace();
    let environment = environment(&prefix, &fixture.root, &[]);
    assert_eq!(
        verified_npm_version(&environment, &workspace),
        Some("11.9.0".to_owned())
    );
}

#[cfg(unix)]
#[test]
fn an_environment_setting_that_moves_the_fetch_proves_nothing() {
    let fixture = Fixture::new("npm-config");
    let prefix = fixture.npm_prefix("11.9.0");
    let workspace = fixture.workspace();
    for name in [
        "npm_config_registry",
        "NPM_CONFIG_ALLOW_GIT",
        "npm_config__cache",
        "npm_config_cafile",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PREFIX",
        "DESTDIR",
        "NODE_TLS_REJECT_UNAUTHORIZED",
    ] {
        let environment = environment(&prefix, &fixture.root, &[name]);
        assert_eq!(
            verified_npm_version(&environment, &workspace),
            None,
            "{name} changes what npm fetches or loads"
        );
    }
}

#[cfg(unix)]
#[test]
fn an_unrelated_setting_still_proves_the_version() {
    let fixture = Fixture::new("unrelated");
    let prefix = fixture.npm_prefix("11.9.0");
    let workspace = fixture.workspace();
    let environment = environment(&prefix, &fixture.root, &["NODE_EXTRA_CA_CERTS"]);
    assert_eq!(
        verified_npm_version(&environment, &workspace),
        Some("11.9.0".to_owned())
    );
}

#[cfg(unix)]
#[test]
fn an_inert_npm_setting_still_proves_the_version() {
    let fixture = Fixture::new("inert");
    let prefix = fixture.npm_prefix("11.9.0");
    let workspace = fixture.workspace();
    for name in [
        "npm_config_cache",
        "NPM_CONFIG_UPDATE_NOTIFIER",
        "npm_config_fund",
    ] {
        let environment = environment(&prefix, &fixture.root, &[name]);
        assert_eq!(
            verified_npm_version(&environment, &workspace),
            Some("11.9.0".to_owned()),
            "{name} changes nothing about where packages come from"
        );
    }
}

#[cfg(unix)]
#[test]
fn an_npmrc_that_moves_the_registry_proves_nothing() {
    let fixture = Fixture::new("npmrc");
    let prefix = fixture.npm_prefix("11.9.0");
    let workspace = fixture.workspace();
    for npmrc in [
        "registry=https://example.test/\n",
        "@acme:registry=https://example.test/\n",
        "strict-ssl=false\n",
        "fund=false\rregistry=https://example.test/\n",
        "ca[]=/tmp/evil.pem\n",
    ] {
        fs::write(fixture.root.join(".npmrc"), npmrc).expect("npmrc must be writable");
        let environment = environment(&prefix, &fixture.root, &[]);
        assert_eq!(
            verified_npm_version(&environment, &workspace),
            None,
            "{npmrc:?} may move the fetch"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_user_config_that_leaves_the_fetch_alone_still_proves_the_version() {
    let fixture = Fixture::new("npmrc-benign");
    let prefix = fixture.npm_prefix("11.9.0");
    let workspace = fixture.workspace();
    fs::write(
        fixture.root.join(".npmrc"),
        "prefix=/tmp/npm-global\n//registry.npmjs.org/:_authToken=x\n",
    )
    .expect("npmrc must be writable");
    let environment = environment(&prefix, &fixture.root, &[]);
    assert_eq!(
        verified_npm_version(&environment, &workspace),
        Some("11.9.0".to_owned())
    );
}

#[cfg(unix)]
#[test]
fn a_commented_npmrc_key_leaves_the_fetch_alone() {
    let fixture = Fixture::new("npmrc-comment");
    let prefix = fixture.npm_prefix("11.9.0");
    let workspace = fixture.workspace();
    fs::write(
        fixture.root.join(".npmrc"),
        "# registry=https://example.invalid\n; proxy=http://example.invalid\nfund=false\n",
    )
    .expect("npmrc must be writable");
    let environment = environment(&prefix, &fixture.root, &[]);
    assert_eq!(
        verified_npm_version(&environment, &workspace),
        Some("11.9.0".to_owned())
    );
}

#[cfg(unix)]
#[test]
fn an_npm_inside_the_workspace_proves_nothing() {
    let fixture = Fixture::new("in-workspace");
    let workspace = fixture.workspace();
    let bin = workspace.join("bin");
    let package = workspace.join("npm");
    fs::create_dir_all(package.join("bin")).expect("package must be creatable");
    fs::create_dir_all(&bin).expect("bin must be creatable");
    write_executable(&package.join("bin").join("npm-cli.js"), "// npm");
    fs::write(
        package.join("package.json"),
        json!({"name": "npm", "version": "11.9.0"}).to_string(),
    )
    .expect("manifest must be writable");
    write_executable(&bin.join("npm"), "#!/bin/sh\n");
    write_executable(&bin.join("node"), "#!/bin/sh\n");
    link(&package.join("bin").join("npm-cli.js"), &bin.join("npm"));
    let environment = environment(&workspace, &fixture.root, &[]);
    assert_eq!(verified_npm_version(&environment, &workspace), None);

    // A workspace `node` ahead of the real one is the same escape.
    let prefix = fixture.npm_prefix("11.9.0");
    let shadow = workspace.join("shadow");
    fs::create_dir_all(&shadow).expect("shadow bin must be creatable");
    write_executable(&shadow.join("node"), "#!/bin/sh\n");
    let shadowed = ExecutionEnvironment::from_value(Some(&json!({
        "environment_names": ["PATH", "HOME"],
        "path": format!(
            "{}:{}",
            shadow.to_string_lossy(),
            prefix.join("bin").to_string_lossy()
        ),
        "home": fixture.root.to_string_lossy(),
    })));
    assert_eq!(verified_npm_version(&shadowed, &workspace), None);
}

#[cfg(unix)]
#[test]
fn a_relative_path_entry_proves_nothing() {
    let fixture = Fixture::new("relative-path");
    let prefix = fixture.npm_prefix("11.9.0");
    let workspace = fixture.workspace();
    let environment = ExecutionEnvironment::from_value(Some(&json!({
        "environment_names": ["PATH", "HOME"],
        "path": format!("node_modules/.bin:{}", prefix.join("bin").to_string_lossy()),
        "home": fixture.root.to_string_lossy(),
    })));
    assert_eq!(verified_npm_version(&environment, &workspace), None);
}

#[cfg(unix)]
#[test]
fn a_shim_that_is_not_npm_cli_proves_nothing() {
    let fixture = Fixture::new("shim");
    let prefix = fixture.npm_prefix("11.9.0");
    let workspace = fixture.workspace();
    let shim = fixture.root.join("shim");
    fs::create_dir_all(&shim).expect("shim dir must be creatable");
    write_executable(&shim.join("npm"), "#!/bin/sh\nexec npm \"$@\"\n");
    write_executable(&shim.join("node"), "#!/bin/sh\n");
    let environment = ExecutionEnvironment::from_value(Some(&json!({
        "environment_names": ["PATH", "HOME"],
        "path": format!(
            "{}:{}",
            shim.to_string_lossy(),
            prefix.join("bin").to_string_lossy()
        ),
        "home": fixture.root.to_string_lossy(),
    })));
    assert_eq!(verified_npm_version(&environment, &workspace), None);
}

#[cfg(unix)]
#[test]
fn an_unlocatable_home_proves_nothing() {
    let fixture = Fixture::new("home");
    let prefix = fixture.npm_prefix("11.9.0");
    let workspace = fixture.workspace();
    for home in [json!(null), json!(""), json!("relative/home")] {
        let environment = ExecutionEnvironment::from_value(Some(&json!({
            "environment_names": ["PATH", "HOME"],
            "path": prefix.join("bin").to_string_lossy(),
            "home": home,
        })));
        assert_eq!(
            verified_npm_version(&environment, &workspace),
            None,
            "{home} cannot locate the user config"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_loader_path_inside_the_workspace_proves_nothing() {
    let fixture = Fixture::new("loader");
    let prefix = fixture.npm_prefix("11.9.0");
    let workspace = fixture.workspace();
    let linked = fixture.root.join("link");
    link(&workspace, &linked);
    // An outside link to a workspace directory that does not exist yet still
    // leads into the workspace once the agent creates it.
    let dangling = fixture.root.join("dangling");
    link(&workspace.join("not-yet"), &dangling);
    for entry in [
        String::new(),
        "lib".to_owned(),
        ".".to_owned(),
        workspace.join("lib").to_string_lossy().into_owned(),
        format!(
            "{}:{}",
            fixture.root.join("lib").to_string_lossy(),
            workspace.to_string_lossy()
        ),
        linked.join("lib").to_string_lossy().into_owned(),
        dangling.join("lib").to_string_lossy().into_owned(),
    ] {
        let environment = ExecutionEnvironment::from_value(Some(&json!({
            "environment_names": ["PATH", "HOME", "LD_LIBRARY_PATH"],
            "path": prefix.join("bin").to_string_lossy(),
            "home": fixture.root.to_string_lossy(),
            "library_search_paths": {"LD_LIBRARY_PATH": entry},
        })));
        assert_eq!(
            verified_npm_version(&environment, &workspace),
            None,
            "{entry:?} can reach the workspace"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_loader_variable_exported_without_its_value_proves_nothing() {
    let fixture = Fixture::new("loader-unstamped");
    let prefix = fixture.npm_prefix("11.9.0");
    let workspace = fixture.workspace();
    let environment = environment(&prefix, &fixture.root, &["LD_LIBRARY_PATH"]);
    assert_eq!(verified_npm_version(&environment, &workspace), None);
}

#[cfg(unix)]
#[test]
fn a_loader_path_outside_the_workspace_still_proves_the_version() {
    let fixture = Fixture::new("loader-outside");
    let prefix = fixture.npm_prefix("11.9.0");
    let workspace = fixture.workspace();
    let library = fixture.root.join("lib");
    fs::create_dir_all(&library).expect("library dir must be creatable");
    let environment = ExecutionEnvironment::from_value(Some(&json!({
        "environment_names": ["PATH", "HOME", "LD_LIBRARY_PATH"],
        "path": prefix.join("bin").to_string_lossy(),
        "home": fixture.root.to_string_lossy(),
        "library_search_paths": {"LD_LIBRARY_PATH": library.to_string_lossy()},
    })));
    assert_eq!(
        verified_npm_version(&environment, &workspace),
        Some("11.9.0".to_owned())
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_loop_in_a_loader_path_proves_nothing() {
    let fixture = Fixture::new("loader-loop");
    let prefix = fixture.npm_prefix("11.9.0");
    let workspace = fixture.workspace();
    let first = fixture.root.join("loop-a");
    let second = fixture.root.join("loop-b");
    link(&second, &first);
    link(&first, &second);
    let environment = ExecutionEnvironment::from_value(Some(&json!({
        "environment_names": ["PATH", "HOME", "LD_LIBRARY_PATH"],
        "path": prefix.join("bin").to_string_lossy(),
        "home": fixture.root.to_string_lossy(),
        "library_search_paths": {"LD_LIBRARY_PATH": first.join("lib").to_string_lossy()},
    })));
    assert_eq!(verified_npm_version(&environment, &workspace), None);
}

#[cfg(unix)]
#[test]
fn an_npm_this_user_cannot_run_is_passed_over() {
    use std::os::unix::fs::PermissionsExt;
    if nix::unistd::geteuid().is_root() {
        // Root may run any file with an execute bit, so there is nothing to see.
        return;
    }
    let fixture = Fixture::new("npm-foreign");
    let prefix = fixture.npm_prefix("11.9.0");
    let blocked = fixture.root.join("blocked");
    fs::create_dir_all(&blocked).expect("blocked dir must be creatable");
    let foreign = blocked.join("npm");
    fs::write(&foreign, "#!/bin/sh\n").expect("file must be writable");
    // Executable for the group only, so the owner cannot run it.
    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o614))
        .expect("mode must be settable");
    let search_path = format!(
        "{}:{}",
        blocked.to_string_lossy(),
        prefix.join("bin").to_string_lossy()
    );
    assert_eq!(
        resolve_executable("npm", &search_path),
        fs::canonicalize(prefix.join("bin").join("npm")).ok()
    );
}

#[test]
fn a_malformed_environment_proves_nothing() {
    let fixture = Fixture::new("malformed");
    let workspace = fixture.workspace();
    for value in [
        json!(null),
        json!("PATH=/usr/bin"),
        json!({"path": "/usr/bin"}),
        json!({"environment_names": ["PATH", 7], "path": "/usr/bin", "home": "/home/agent"}),
    ] {
        let environment = ExecutionEnvironment::from_value(Some(&value));
        assert_eq!(
            verified_npm_version(&environment, &workspace),
            None,
            "{value} is not a usable stamp"
        );
    }
}

#[test]
fn npm_config_names_are_read_the_way_npm_reads_them() {
    assert!(changes_npm("npm_config_registry"));
    assert!(changes_npm("NPM_CONFIG_CA"));
    assert!(!changes_npm("npm_config_update_notifier"));
    assert!(!changes_npm("npm_config_loglevel"));
    assert!(changes_npm("NODE_PATH"));
    assert!(changes_npm("prefix"));
    assert!(!changes_npm("PATH"));
    assert!(!changes_npm("HOME"));
}

#[cfg(unix)]
#[test]
fn an_output_filter_inside_the_workspace_is_refused() {
    let fixture = Fixture::new("filters");
    let workspace = fixture.workspace();
    let outside = fixture.root.join("bin");
    fs::create_dir_all(&outside).expect("bin must be creatable");
    write_executable(&outside.join("tail"), "#!/bin/sh\n");
    let planted = workspace.join("bin");
    fs::create_dir_all(&planted).expect("planted bin must be creatable");
    write_executable(&planted.join("tail"), "#!/bin/sh\n");

    let honest = ExecutionEnvironment::from_value(Some(&json!({
        "environment_names": ["PATH"],
        "path": outside.to_string_lossy(),
    })));
    assert!(filters_outside_workspace(
        &["tail".to_owned()],
        &honest,
        &workspace
    ));

    let planted_first = ExecutionEnvironment::from_value(Some(&json!({
        "environment_names": ["PATH"],
        "path": format!(
            "{}:{}",
            planted.to_string_lossy(),
            outside.to_string_lossy()
        ),
    })));
    assert!(!filters_outside_workspace(
        &["tail".to_owned()],
        &planted_first,
        &workspace
    ));
}

#[test]
fn no_output_filter_needs_no_program() {
    let fixture = Fixture::new("no-filters");
    let workspace = fixture.workspace();
    let environment = ExecutionEnvironment::from_value(Some(&json!({"path": ""})));
    assert!(filters_outside_workspace(&[], &environment, &workspace));
}
