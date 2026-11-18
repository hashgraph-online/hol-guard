use std::fs;

use serde_json::json;

use super::super::Ctx;
#[cfg(unix)]
use super::scoped_probe_dir;
use super::{attested, REINSTALL};
use crate::pyjson::PyVal;

fn ctx(home: &std::path::Path, caller: serde_json::Value) -> Ctx {
    Ctx::parse(Some(&json!({
        "home": home,
        "workspace": null,
        "guard_home": home.join(".hol-guard"),
        "home_override_explicit": false,
        "cwd": home,
        "user_home": home,
        "env": {"PATH": ""},
        "caller": caller,
    })))
    .unwrap()
}

fn launcher(home: &std::path::Path) -> std::path::PathBuf {
    let path = home.join("hol-guard-core");
    fs::write(&path, "#!/bin/sh\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    path
}

#[test]
fn a_frozen_guard_is_attested_by_its_launcher_identity() {
    let home = tempfile::tempdir().unwrap();
    let path = launcher(home.path());
    let ctx = ctx(
        home.path(),
        json!({"executable": "/g/core", "frozen": true, "frozen_launcher": path, "version": "9.9.9"}),
    );
    let attested = attested(&ctx, false).unwrap().unwrap();
    let text = path.to_str().unwrap().to_owned();
    assert_eq!(attested.command, vec![text.clone()]);
    assert!(attested.python.is_none());
    assert_eq!(
        attested.hook_prefix(),
        vec![text.clone(), "hook".to_owned()]
    );
    let identity = attested.identity.to_json().unwrap();
    assert_eq!(identity["runtime"], "frozen-core");
    assert_eq!(identity["guard_version"], "9.9.9");
    assert_eq!(identity["package_file"], serde_json::Value::Null);
    assert_eq!(identity["interpreter"]["invocation_path"], json!(text));
    assert_eq!(identity["interpreter"]["invocation_type"], "file");
    let PyVal::Dict(fields) = &attested.identity else {
        panic!("the manifest is a dict");
    };
    let keys: Vec<&str> = fields.iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(
        keys,
        [
            "schema",
            "runtime",
            "command",
            "entry_point",
            "guard_version",
            "package_file",
            "package_root",
            "hol_distribution_root",
            "interpreter"
        ]
    );
}

#[test]
fn a_frozen_launcher_that_is_missing_names_the_identity_error() {
    let home = tempfile::tempdir().unwrap();
    let ctx = ctx(
        home.path(),
        json!({"frozen": true, "frozen_launcher": home.path().join("absent"), "version": "1"}),
    );
    let error = attested(&ctx, false).unwrap().err().unwrap();
    assert!(
        error.starts_with("guard_hook_python_interpreter_"),
        "{error}"
    );
}

#[test]
fn a_python_guard_without_package_facts_asks_for_a_reinstall() {
    let home = tempfile::tempdir().unwrap();
    for facts in [
        json!(null),
        json!({"error": "guard_hook_python_active_package_unavailable"}),
    ] {
        let ctx = ctx(
            home.path(),
            json!({"executable": "/py/bin/python", "frozen": false, "version": "1", "attest_facts": facts}),
        );
        for scoped in [false, true] {
            assert_eq!(attested(&ctx, scoped).unwrap().err().unwrap(), REINSTALL);
        }
    }
}

#[test]
fn a_python_guard_whose_interpreter_is_missing_asks_for_a_reinstall() {
    let home = tempfile::tempdir().unwrap();
    let ctx = ctx(
        home.path(),
        json!({
            "executable": home.path().join("python"),
            "frozen": false,
            "version": "1",
            "attest_facts": {
                "package_file": home.path().join("pkg").join("__init__.py"),
                "package_root": null,
                "version": "1",
                "cryptography_root": null,
                "hol": null,
            },
        }),
    );
    assert_eq!(attested(&ctx, true).unwrap().err().unwrap(), REINSTALL);
}

#[cfg(unix)]
#[test]
fn a_scoped_probe_directory_is_private_like_pythons() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let context = ctx(
        home.path(),
        json!({"executable": "/g/python", "frozen": false}),
    );
    let directory = scoped_probe_dir(&context).unwrap();
    let mode = fs::metadata(directory.path()).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
}
