use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::{command, dispatch, verify, NAME, SCRIPT, SHELL};
use crate::native_install_verdict::{Invocation, Ran, Runner};

/// Answers `codesign` with the team each path is signed by; a path with no
/// entry does not verify.
struct Signed(BTreeMap<PathBuf, &'static str>);

impl Runner for Signed {
    fn run(&mut self, invocation: &Invocation) -> io::Result<Ran> {
        let path = Path::new(invocation.arguments.last().expect("a path"));
        let team = self.0.get(path);
        let stderr = team.map(|team| format!("TeamIdentifier={team}\n"));
        Ok(Ran {
            success: team.is_some(),
            stdout: Vec::new(),
            stderr: stderr.unwrap_or_default().into_bytes(),
        })
    }
}

struct Fixture {
    _home: tempfile::TempDir,
    bundle: PathBuf,
    proxy: PathBuf,
    core: PathBuf,
}

fn fixture() -> Fixture {
    let home = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(home.path()).unwrap();
    let bundle = root.join("HOL Guard.app");
    let macos = bundle.join("Contents/MacOS");
    fs::create_dir_all(&macos).unwrap();
    let (proxy, core) = (macos.join("HOL Guard"), macos.join("hol-guard"));
    for path in [&proxy, &core] {
        fs::write(path, "binary").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    Fixture {
        _home: home,
        bundle,
        proxy,
        core,
    }
}

fn signed(fixture: &Fixture, core_team: &'static str) -> Signed {
    Signed(BTreeMap::from([
        (fixture.bundle.clone(), "TEAMID"),
        (fixture.proxy.clone(), "TEAMID"),
        (fixture.core.clone(), core_team),
    ]))
}

fn request(fixture: &Fixture, desktop: Value, require: bool) -> serde_json::Map<String, Value> {
    let value = json!({
        "op": "command",
        "core": fixture.core,
        "config": "{\"harness\":\"grok\"}",
        "require_proxy": require,
        "desktop": desktop,
        "proxy": fixture.proxy,
    });
    value.as_object().unwrap().clone()
}

fn path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
fn a_same_team_bundle_launches_through_the_checking_script() {
    let fixture = fixture();
    let answer = command(
        &request(&fixture, json!("1"), true),
        true,
        &mut signed(&fixture, "TEAMID"),
    )
    .unwrap();
    assert_eq!(
        answer["argv"],
        json!([
            SHELL,
            "-c",
            SCRIPT,
            NAME,
            path(&fixture.proxy),
            "TEAMID",
            path(&fixture.bundle),
            "{\"harness\":\"grok\"}",
            path(&fixture.core),
            "1",
        ])
    );
    assert!(SCRIPT.starts_with("set -u\n") && SCRIPT.ends_with("exit \"$status\""));
}

#[test]
fn anything_short_of_one_verified_team_keeps_the_core_bridge() {
    let fixture = fixture();
    let none = json!({ "argv": null });
    let mismatched = signed(&fixture, "OTHER");
    let mut unsigned = signed(&fixture, "TEAMID");
    unsigned.0.remove(&fixture.bundle);
    for (mut runner, desktop, macos) in [
        (mismatched, json!("1"), true),
        (unsigned, json!("1"), true),
        (signed(&fixture, "TEAMID"), json!(null), true),
        (signed(&fixture, "TEAMID"), json!("0"), true),
        (signed(&fixture, "TEAMID"), json!("1"), false),
    ] {
        let answer = command(&request(&fixture, desktop, false), macos, &mut runner).unwrap();
        assert_eq!(answer, none);
    }
}

#[test]
fn an_untrusted_layout_keeps_the_core_bridge() {
    let none = json!({ "argv": null });
    let writable = fixture();
    fs::set_permissions(&writable.proxy, fs::Permissions::from_mode(0o777)).unwrap();
    let open_bundle = fixture();
    fs::set_permissions(
        open_bundle.bundle.join("Contents"),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    let linked = fixture();
    fs::remove_file(&linked.proxy).unwrap();
    std::os::unix::fs::symlink(&linked.core, &linked.proxy).unwrap();
    let mut apart = fixture();
    let elsewhere = apart.bundle.join("Contents/Helpers/HOL Guard");
    fs::create_dir(elsewhere.parent().unwrap()).unwrap();
    fs::rename(&apart.proxy, &elsewhere).unwrap();
    apart.proxy = elsewhere;
    let plain = fixture();
    fs::set_permissions(&plain.core, fs::Permissions::from_mode(0o644)).unwrap();
    for fixture in [writable, open_bundle, linked, apart, plain] {
        let mut runner = signed(&fixture, "TEAMID");
        let answer = command(&request(&fixture, json!("1"), false), true, &mut runner).unwrap();
        assert_eq!(answer, none, "{:?}", fixture.proxy);
    }
}

fn stored(fixture: &Fixture, team: &str) -> serde_json::Map<String, Value> {
    let args = json!([
        SHELL,
        "-c",
        SCRIPT,
        NAME,
        fixture.proxy,
        team,
        fixture.bundle,
        "{\"harness\":\"grok\"}",
        fixture.core,
    ]);
    json!({ "op": "verify", "args": args })
        .as_object()
        .unwrap()
        .clone()
}

#[test]
fn a_stored_launch_is_trusted_only_over_its_verified_paths_and_team() {
    let fixture = fixture();
    let answer = verify(
        &stored(&fixture, "TEAMID"),
        true,
        &mut signed(&fixture, "TEAMID"),
    )
    .unwrap();
    assert_eq!(
        answer,
        json!({ "config": "{\"harness\":\"grok\"}", "core": path(&fixture.core) })
    );
    let unverified = json!({ "config": null, "core": null });
    let mut altered = stored(&fixture, "TEAMID");
    altered["args"][2] = json!("echo hol-guard hook");
    let mut ten = stored(&fixture, "TEAMID");
    ten["args"].as_array_mut().unwrap().push(json!("0"));
    let mut other_bundle = stored(&fixture, "TEAMID");
    other_bundle["args"][6] = json!(fixture.bundle.join("Contents"));
    for (request, core_team, macos) in [
        (stored(&fixture, "TEAMID"), "OTHER", true),
        (stored(&fixture, "OTHER"), "OTHER", true),
        (stored(&fixture, "TEAMID"), "TEAMID", false),
        (altered, "TEAMID", true),
        (ten, "TEAMID", true),
        (other_bundle, "TEAMID", true),
    ] {
        let answer = verify(&request, macos, &mut signed(&fixture, core_team)).unwrap();
        assert_eq!(answer, unverified, "{request:?}");
    }
}

#[test]
fn malformed_requests_are_refused() {
    let fixture = fixture();
    let mut extra = request(&fixture, json!("1"), false);
    extra.insert("more".to_owned(), json!(1));
    let mut missing = request(&fixture, json!("1"), false);
    missing.remove("proxy");
    let mut flag = request(&fixture, json!("1"), false);
    flag.insert("require_proxy".to_owned(), json!("yes"));
    let mut desktop = request(&fixture, json!(1), false);
    desktop.insert("op".to_owned(), json!("command"));
    for args in [extra, missing, flag, desktop] {
        assert!(dispatch(&Value::Object(args)).is_err());
    }
    for args in [
        json!({"op": "verify", "args": ["/bin/sh", 1]}),
        json!({"op": "verify"}),
        json!({"op": "script", "more": 1}),
        json!({"op": "other"}),
    ] {
        assert!(dispatch(&args).is_err(), "{args}");
    }
    assert_eq!(
        dispatch(&json!({"op": "script"})).unwrap(),
        json!({ "script": SCRIPT, "name": NAME })
    );
}
