use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::{expectation, probe_dir, Facts};

fn touch(path: &Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, "").unwrap();
}

/// A site directory holding the package and `cryptography`, canonical.
fn site() -> (tempfile::TempDir, PathBuf) {
    let home = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(home.path()).unwrap();
    touch(&root.join("site/codex_plugin_scanner/__init__.py"));
    touch(&root.join("site/cryptography/__init__.py"));
    (home, root)
}

fn hol(root: &Path, version: &str, entry_point: Value, direct_url: Value) -> Value {
    json!({"root": root, "version": version, "entry_point": entry_point, "direct_url": direct_url})
}

fn facts(package_file: &Path, package_root: Value, cryptography: Value, hol: Value) -> Value {
    json!({
        "package_file": package_file,
        "package_root": package_root,
        "version": "1.0",
        "cryptography_root": cryptography,
        "hol": hol,
    })
}

fn expect(value: &Value) -> Result<Value, &'static str> {
    expectation(&Facts::parse(Some(value)).unwrap()).map(Value::Object)
}

const ENTRY: &str = "codex_plugin_scanner.cli:main";

#[test]
fn an_installed_wheel_imports_from_its_one_site_directory() {
    let (_home, root) = site();
    let site = root.join("site");
    let package = site.join("codex_plugin_scanner/__init__.py");
    let request = facts(
        &package,
        json!(site),
        json!(site),
        hol(&site, "1.0", json!(ENTRY), Value::Null),
    );
    assert_eq!(
        expect(&request).unwrap(),
        json!({
            "package_file": package,
            "package_root": site,
            "cryptography_file": site.join("cryptography/__init__.py"),
            "import_roots": [site],
            "hol_distribution_root": site,
            "cryptography_distribution_root": site,
            "version": "1.0",
            "entry_point": ENTRY,
        })
    );
    let other = facts(
        &package,
        json!(root),
        json!(site),
        hol(&site, "1.0", json!(ENTRY), Value::Null),
    );
    assert_eq!(
        expect(&other),
        Err("guard_hook_python_package_root_mismatch")
    );
}

#[test]
fn a_distribution_at_another_version_or_entry_point_is_a_mismatch() {
    let (_home, root) = site();
    let site = root.join("site");
    let package = site.join("codex_plugin_scanner/__init__.py");
    for hol in [
        hol(&site, "2.0", json!(ENTRY), Value::Null),
        hol(&site, "1.0", json!("other:main"), Value::Null),
        hol(&site, "1.0", Value::Null, Value::Null),
    ] {
        let request = facts(&package, Value::Null, json!(site), hol);
        assert_eq!(
            expect(&request),
            Err("guard_hook_python_hol_guard_distribution_mismatch")
        );
    }
    let absent = facts(&package, Value::Null, json!(site), Value::Null);
    assert_eq!(
        expect(&absent),
        Err("guard_hook_python_hol_guard_distribution_unavailable")
    );
}

#[test]
fn cryptography_must_be_inside_its_distribution() {
    let (_home, root) = site();
    let site = root.join("site");
    let package = site.join("codex_plugin_scanner/__init__.py");
    let hol = || hol(&site, "1.0", json!(ENTRY), Value::Null);
    for (cryptography, reason) in [
        (
            Value::Null,
            "guard_hook_python_cryptography_distribution_unavailable",
        ),
        (
            json!(root.join("absent")),
            "guard_hook_python_cryptography_distribution_unavailable",
        ),
        (json!(root), "guard_hook_python_cryptography_unavailable"),
    ] {
        let request = facts(&package, Value::Null, cryptography, hol());
        assert_eq!(expect(&request), Err(reason));
    }
    #[cfg(unix)]
    {
        fs::create_dir(root.join("elsewhere")).unwrap();
        touch(&root.join("other/cryptography/__init__.py"));
        std::os::unix::fs::symlink(
            root.join("other/cryptography"),
            root.join("elsewhere/cryptography"),
        )
        .unwrap();
        let request = facts(&package, Value::Null, json!(root.join("elsewhere")), hol());
        assert_eq!(
            expect(&request),
            Err("guard_hook_python_cryptography_distribution_mismatch")
        );
    }
}

#[test]
fn an_editable_checkout_imports_its_src_directory() {
    let (_home, root) = site();
    let site = root.join("site");
    let checkout = root.join("my checkout");
    let src = checkout.join("src");
    let package = src.join("codex_plugin_scanner/__init__.py");
    touch(&package);
    touch(&checkout.join("pyproject.toml"));
    let bare = facts(&package, Value::Null, json!(site), Value::Null);
    let answer = expect(&bare).unwrap();
    assert_eq!(answer["import_roots"], json!([src, site]));
    assert_eq!(answer["hol_distribution_root"], Value::Null);

    let url = |url: String| json!(json!({"url": url, "dir_info": {"editable": true}}).to_string());
    let encoded = format!(
        "file://{}",
        checkout.to_string_lossy().replace(' ', "%2520")
    );
    for direct_url in [
        url(format!("file://{}", checkout.to_string_lossy())),
        url(format!("file://localhost{}", checkout.to_string_lossy())),
        url(encoded),
    ] {
        let request = facts(
            &package,
            Value::Null,
            json!(site),
            hol(&site, "1.0", json!(ENTRY), direct_url),
        );
        let answer = expect(&request).unwrap();
        assert_eq!(answer["import_roots"], json!([src, site]), "{request}");
        assert_eq!(answer["hol_distribution_root"], json!(site));
    }
    let plain = checkout.to_string_lossy().into_owned();
    for direct_url in [
        Value::Null,
        json!("not json"),
        json!(
            json!({"url": format!("file://{plain}"), "dir_info": {"editable": false}}).to_string()
        ),
        url(format!("file://host{plain}")),
        url(format!("file://{plain}?x=1")),
        url(format!("file://{plain}#top")),
        url(format!("file://{plain};x")),
        url(format!("https://{plain}")),
        url(format!("file://{}", root.join("absent").to_string_lossy())),
    ] {
        let request = facts(
            &package,
            Value::Null,
            json!(site),
            hol(&site, "1.0", json!(ENTRY), direct_url),
        );
        assert_eq!(
            expect(&request),
            Err("guard_hook_python_hol_guard_distribution_mismatch"),
            "{request}"
        );
    }
}

#[test]
fn malformed_facts_are_refused() {
    let package = Path::new("/p/codex_plugin_scanner/__init__.py");
    let good = facts(package, Value::Null, json!("/p"), Value::Null);
    let mut extra = good.clone();
    extra["more"] = json!(1);
    for value in [
        facts(Path::new("relative"), Value::Null, json!("/p"), Value::Null),
        facts(package, json!("relative"), json!("/p"), Value::Null),
        facts(package, Value::Null, json!(1), Value::Null),
        facts(package, Value::Null, json!("/p"), json!({"root": "/p"})),
        facts(
            package,
            Value::Null,
            json!("/p"),
            hol(Path::new("/p"), "1.0", json!(1), Value::Null),
        ),
        extra,
        json!([]),
    ] {
        assert!(Facts::parse(Some(&value)).is_err(), "{value}");
    }
    assert!(Facts::parse(Some(&good)).is_ok());
    assert!(Facts::parse(None).is_err());
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).unwrap().mode() & 0o777
}

#[cfg(unix)]
#[test]
fn the_guard_home_probe_directory_is_made_private() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(home.path()).unwrap();
    let guard_home = root.join("guard");
    let made = probe_dir(Some(&json!({"guard_home": guard_home})))
        .unwrap()
        .unwrap();
    assert_eq!(made, guard_home.join("runtime/python-probe"));
    assert_eq!(mode(&guard_home), 0o700);
    assert_eq!(mode(&made), 0o700);
    fs::set_permissions(&made, fs::Permissions::from_mode(0o755)).unwrap();
    let again = probe_dir(Some(&json!({"guard_home": guard_home})))
        .unwrap()
        .unwrap();
    assert_eq!(mode(&again), 0o700, "a widened directory is narrowed again");

    fs::set_permissions(&guard_home, fs::Permissions::from_mode(0o770)).unwrap();
    assert_eq!(
        probe_dir(Some(&json!({"guard_home": guard_home}))).unwrap(),
        Err("guard_hook_python_neutral_cwd_unavailable")
    );
    fs::set_permissions(&guard_home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir(guard_home.join("runtime/python-probe")).unwrap();
    std::os::unix::fs::symlink(&root, guard_home.join("runtime/python-probe")).unwrap();
    assert_eq!(
        probe_dir(Some(&json!({"guard_home": guard_home}))).unwrap(),
        Err("guard_hook_python_neutral_cwd_unavailable")
    );
}

#[cfg(unix)]
#[test]
fn a_preparation_scope_must_be_a_private_directory() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(home.path()).unwrap();
    let scope = root.join("scope");
    fs::create_dir(&scope).unwrap();
    fs::set_permissions(&scope, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        probe_dir(Some(&json!({"scoped": scope}))).unwrap(),
        Ok(scope.clone())
    );
    std::os::unix::fs::symlink(&scope, root.join("link")).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    for path in [root.join("link"), root.clone(), root.join("absent")] {
        assert_eq!(
            probe_dir(Some(&json!({"scoped": path}))).unwrap(),
            Err("guard_hook_python_neutral_cwd_unavailable"),
            "{path:?}"
        );
    }
    for value in [
        json!({}),
        json!({"scoped": "relative"}),
        json!({"scoped": scope, "guard_home": root}),
        json!({"other": scope}),
    ] {
        assert!(probe_dir(Some(&value)).is_err(), "{value}");
    }
}
