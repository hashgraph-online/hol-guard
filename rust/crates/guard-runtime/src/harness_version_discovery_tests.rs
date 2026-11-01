use std::os::unix::fs::{symlink, PermissionsExt};
use std::time::Instant;

use super::*;

const PACKAGE: &str = "@oh-my-pi/pi-coding-agent";

struct Layout {
    root: tempfile::TempDir,
}

impl Layout {
    fn new() -> Self {
        let layout = Self {
            root: tempfile::tempdir().expect("tempdir"),
        };
        fs::create_dir_all(layout.home()).expect("home");
        fs::create_dir_all(layout.guard_home()).expect("guard home");
        fs::create_dir_all(layout.path_dir()).expect("path dir");
        layout
    }

    fn real(&self) -> PathBuf {
        fs::canonicalize(self.root.path()).expect("canonical root")
    }

    fn home(&self) -> PathBuf {
        self.real().join("home")
    }

    fn guard_home(&self) -> PathBuf {
        self.real().join("guard-home")
    }

    fn path_dir(&self) -> PathBuf {
        self.real().join("path-bin")
    }

    fn request(&self, op: &str) -> Value {
        json!({
            "schema": SCHEMA,
            "op": op,
            "harness": "omp",
            "home_dir": self.home(),
            "guard_home": self.guard_home(),
            "environment": { "PATH": self.path_dir() },
            "now": 1_800_000_000.5,
        })
    }

    fn observe(&self) -> Value {
        run(&self.request("observe")).expect("observe")
    }

    fn changed(&self, observed: &Value) -> bool {
        let mut request = self.request("identity-changed");
        request["candidates"] = observed["candidates"].clone();
        request["identity"] = observed["identity"].clone();
        run(&request).expect("identity-changed")["changed"]
            .as_bool()
            .expect("changed flag")
    }
}

fn run(request: &Value) -> Result<Value, String> {
    let bytes = run_command(request.to_string().as_bytes())?;
    Ok(serde_json::from_slice(&bytes).expect("answer is JSON"))
}

fn script(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("script dir");
    fs::write(path, format!("#!/bin/sh\n{body}\n")).expect("script");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod");
}

fn package(directory: &Path, name: &str, version: &str) -> PathBuf {
    fs::create_dir_all(directory.join("bin")).expect("package dir");
    fs::write(
        directory.join("package.json"),
        json!({ "name": name, "version": version }).to_string(),
    )
    .expect("package.json");
    let entry = directory.join("bin").join("omp.js");
    fs::write(&entry, b"#!/usr/bin/env node\n").expect("entry");
    entry
}

#[test]
fn an_unsupported_harness_is_never_guessed() {
    let layout = Layout::new();
    let mut request = layout.request("observe");
    request["harness"] = json!("cursor");
    let observed = run(&request).expect("observe");
    assert_eq!(observed["state"], "unavailable");
    assert_eq!(observed["reason"], "discovery_unsupported");
    assert_eq!(observed["observed_at"], 1_800_000_000.5);
}

#[test]
fn no_installation_is_executable_missing() {
    let observed = Layout::new().observe();
    assert_eq!(observed["state"], "unavailable");
    assert_eq!(observed["reason"], "executable_missing");
    assert_eq!(observed["installation_id"], Value::Null);
}

#[test]
fn package_metadata_wins_over_any_probe() {
    let layout = Layout::new();
    let entry = package(&layout.real().join("pkg"), PACKAGE, "14.1.0");
    let link = layout.home().join(".bun").join("bin").join("omp");
    fs::create_dir_all(link.parent().expect("parent")).expect("bun bin");
    symlink(&entry, &link).expect("symlink");

    let observed = layout.observe();

    assert_eq!(observed["state"], "observed");
    assert_eq!(observed["version"], "14.1.0");
    assert_eq!(observed["source"], "package-metadata");
    assert_eq!(observed["reason"], Value::Null);
    let entry_text = entry.to_string_lossy().into_owned();
    assert_eq!(observed["candidates"], json!([entry_text]));
    let digest = hex::encode(Sha256::digest(format!("omp\0{entry_text}").as_bytes()));
    assert_eq!(observed["installation_id"], &digest[..24]);
    let manifest = layout.real().join("pkg").join("package.json");
    assert_eq!(
        observed["identity"][0][0],
        manifest.to_str().expect("utf-8")
    );
    assert!(
        !layout.guard_home().join("runtime").exists(),
        "no probe ran"
    );
}

#[test]
fn a_foreign_or_broken_package_json_is_not_trusted() {
    let layout = Layout::new();
    // A package.json for another package is skipped on the walk up.
    let entry = package(&layout.real().join("pkg"), "left-pad", "1.0.0");
    let link = layout.home().join(".local").join("bin").join("omp");
    fs::create_dir_all(link.parent().expect("parent")).expect("local bin");
    symlink(&entry, &link).expect("symlink");
    let observed = layout.observe();
    assert_eq!(observed["reason"], "metadata_unavailable");
    assert_eq!(observed["source"], "none");

    fs::write(layout.real().join("pkg").join("package.json"), b"{broken").expect("broken");
    assert_eq!(layout.observe()["reason"], "metadata_malformed");

    package(&layout.real().join("pkg"), PACKAGE, "not-a-version");
    assert_eq!(layout.observe()["reason"], "metadata_malformed");
}

#[test]
fn a_standalone_binary_is_probed_in_a_private_directory() {
    let layout = Layout::new();
    script(
        &layout.path_dir().join("omp"),
        "pwd > \"$HOME/cwd\"; echo \"omp/2.3.4-rc.1\"",
    );

    let observed = layout.observe();

    assert_eq!(observed["state"], "observed");
    assert_eq!(observed["version"], "2.3.4-rc.1");
    assert_eq!(observed["source"], "version-probe");
    let probe_dir = layout
        .guard_home()
        .join("runtime")
        .join("harness-version-probe");
    let cwd = fs::read_to_string(layout.home().join("cwd")).expect("cwd");
    assert_eq!(cwd.trim(), probe_dir.to_str().expect("utf-8"));
    let mode = fs::metadata(&probe_dir)
        .expect("probe dir")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
}

#[test]
fn a_probe_that_fails_or_rambles_has_no_version() {
    let layout = Layout::new();
    let omp = layout.path_dir().join("omp");
    for (body, reason) in [
        ("echo omp 1.2.3; exit 1", "probe_failed"),
        ("echo 'omp 1.2.3 (build 7)'", "banner_malformed"),
        ("printf 'omp\\n1.2.3\\n'", "banner_malformed"),
        ("printf 'omp\\r1.2.3'", "banner_malformed"),
        ("printf '\\377\\376 1.2.3'", "banner_malformed"),
    ] {
        script(&omp, body);
        let observed = layout.observe();
        assert_eq!(observed["state"], "unavailable", "{body}");
        assert_eq!(observed["reason"], reason, "{body}");
    }
}

#[test]
fn a_probe_that_hangs_times_out() {
    let layout = Layout::new();
    script(&layout.path_dir().join("omp"), "exec /bin/sleep 30");
    let started = Instant::now();
    assert_eq!(layout.observe()["reason"], "probe_timeout");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_script_without_a_package_is_never_run() {
    let layout = Layout::new();
    let marker = layout.home().join("ran");
    let entry = layout.path_dir().join("omp.js");
    script(&entry, &format!("touch {}", marker.display()));
    let link = layout.home().join(".local").join("bin").join("omp");
    fs::create_dir_all(link.parent().expect("parent")).expect("local bin");
    symlink(&entry, &link).expect("symlink");

    let observed = layout.observe();

    assert_eq!(observed["reason"], "metadata_unavailable");
    assert!(!marker.exists());
}

#[test]
fn installs_that_disagree_are_ambiguous() {
    let layout = Layout::new();
    script(&layout.path_dir().join("omp"), "echo 1.2.3");
    script(
        &layout.home().join(".local").join("bin").join("omp"),
        "echo 1.2.4",
    );
    let observed = layout.observe();
    assert_eq!(observed["state"], "ambiguous");
    assert_eq!(observed["reason"], "multiple_installations");
    assert_eq!(observed["version"], Value::Null);
    assert_eq!(observed["candidates"].as_array().map(Vec::len), Some(2));

    script(
        &layout.home().join(".local").join("bin").join("omp"),
        "echo v1.2.3",
    );
    assert_eq!(layout.observe()["version"], "1.2.3");
}

#[test]
fn a_guard_shim_on_path_is_not_the_harness() {
    let layout = Layout::new();
    let shim_dir = layout.guard_home().join("bin");
    script(&shim_dir.join("omp"), "echo 9.9.9");
    let mut request = layout.request("observe");
    request["environment"]["PATH"] = json!(shim_dir);
    assert_eq!(
        run(&request).expect("observe")["reason"],
        "executable_missing"
    );
}

#[test]
fn identity_changes_when_an_install_is_replaced_or_added() {
    let layout = Layout::new();
    let omp = layout.path_dir().join("omp");
    script(&omp, "echo 1.2.3");
    let observed = layout.observe();
    assert!(!layout.changed(&observed));

    script(&omp, "echo 1.2.30");
    assert!(layout.changed(&observed));

    let observed = layout.observe();
    script(
        &layout.home().join(".bun").join("bin").join("omp"),
        "echo 1.2.30",
    );
    assert!(layout.changed(&observed));
}

#[test]
fn banners_parse_only_in_the_known_shape() {
    let source = &VERSION_SOURCES[0];
    for (banner, expected) in [
        ("1.2.3\n", Some("1.2.3")),
        ("  omp: v1.2.3  ", Some("1.2.3")),
        (
            "@oh-my-pi/pi-coding-agent/1.2.3+build.5",
            Some("1.2.3+build.5"),
        ),
        ("OMP 0.0.1-beta", Some("0.0.1-beta")),
        ("oh-my-pi v18.8.3", Some("18.8.3")),
        ("omp 18.8.3\nsecond line", None),
        ("18.8.3 18.8.4", None),
        ("other-tool 18.8.3", None),
        ("omp 18.8.3 (beta)", None),
        ("\r\n\nomp 1.2.3\r\n", Some("1.2.3")),
        ("other 1.2.3", None),
        ("omp 1.2.3 1.2.4", None),
        ("omp 01.2.3", None),
        ("omp 1.2.1234567", None),
        ("omp 1.2", None),
        ("omp\u{2028}1.2.3", None),
        ("", None),
    ] {
        let parsed = parse_banner(source, banner).map(|version| version.canonical);
        assert_eq!(parsed.as_deref(), expected, "{banner:?}");
    }
    assert!(parse_banner(
        source,
        &format!("omp 1.2.3{}", " ".repeat(MAX_BANNER_BYTES))
    )
    .is_none());
}

#[test]
fn malformed_requests_are_refused() {
    let layout = Layout::new();
    let refused = Err(invalid());
    let mut relative = layout.request("observe");
    relative["home_dir"] = json!("home");
    assert_eq!(run(&relative), refused);
    let mut unknown_op = layout.request("observe");
    unknown_op["op"] = json!("probe");
    assert_eq!(run(&unknown_op), refused);
    let mut extra = layout.request("observe");
    extra["argv"] = json!(["omp"]);
    assert_eq!(run(&extra), refused);
    let mut schema = layout.request("observe");
    schema["schema"] = json!("harness-version-discovery.v0");
    assert_eq!(run(&schema), refused);
}

#[test]
fn the_search_path_follows_shutil_which() {
    let environment = |path: Option<&str>| {
        path.map(|path| BTreeMap::from([("PATH".to_owned(), path.to_owned())]))
            .unwrap_or_default()
    };
    // No `PATH` searches the platform default; an empty one searches nothing.
    assert_eq!(
        search_path(&environment(None)).as_deref(),
        Some(DEFAULT_SEARCH_PATH)
    );
    assert_eq!(search_path(&environment(Some(""))), None);
    // A relative entry is found from this process's directory.
    let cwd = std::env::current_dir().expect("cwd");
    assert_eq!(
        search_path(&environment(Some("/opt/bin:bin"))),
        Some(format!("/opt/bin:{}", cwd.join("bin").display()))
    );
}
