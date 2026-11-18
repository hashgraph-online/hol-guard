use std::fs;

use serde_json::{json, Value};
use tempfile::TempDir;

use super::super::Ctx;
#[cfg(unix)]
use super::launcher_env;
use super::{bridge, proxy_guard_home, python_launch, relay_launch, RELAY_FEATURE};

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn ctx(frozen: bool, native_runtime: Value, env: Value) -> Ctx {
    Ctx::parse(Some(&json!({
        "home": "/u/home",
        "workspace": null,
        "guard_home": "/u/home/.hol-guard",
        "home_override_explicit": false,
        "cwd": "/work",
        "user_home": "/u/home",
        "env": env,
        "caller": {
            "executable": "/py/bin/python",
            "executable_resolved": "/py/bin/python3.12",
            "frozen": frozen,
            "launcher": "/py/bin/python",
            "package_root": "/site",
            "version": "1.0.0",
            "native_runtime": native_runtime,
        },
    })))
    .unwrap()
}

fn runtime(features: &[&str]) -> Value {
    json!({"path": "/rt/hol-guard-runtime", "size": 3, "sha256": "0".repeat(64), "features": features})
}

fn proxy_args() -> Vec<String> {
    strings(&[
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "hermes-mcp-proxy",
        "--guard-home",
        "/g",
        "--server-name",
        "s",
    ])
}

#[test]
fn a_source_caller_relays_through_the_runtime_it_validated() {
    let ctx = ctx(false, runtime(&[RELAY_FEATURE]), json!({}));
    let (command, args) = relay_launch(&ctx, "/py/bin/python", &proxy_args()).unwrap();
    assert_eq!(command, "/rt/hol-guard-runtime");
    let mut expected = strings(&["mcp-relay", "/py/bin/python"]);
    expected.extend(proxy_args());
    assert_eq!(args, expected);
    assert_eq!(
        python_launch(Some(&command), &args),
        (Some("/py/bin/python".to_owned()), proxy_args())
    );
}

#[test]
fn no_relay_feature_or_runtime_keeps_the_python_proxy() {
    for stamp in [Value::Null, runtime(&["other"])] {
        let ctx = ctx(false, stamp, json!({}));
        let launch = relay_launch(&ctx, "/py/bin/python", &proxy_args()).unwrap();
        assert_eq!(launch, ("/py/bin/python".to_owned(), proxy_args()));
    }
    let ctx = ctx(false, runtime(&[RELAY_FEATURE]), json!({}));
    let other = strings(&["-m", "codex_plugin_scanner.cli", "guard", "mcp-proxy"]);
    assert_eq!(
        relay_launch(&ctx, "/py/bin/python", &other).unwrap(),
        ("/py/bin/python".to_owned(), other.clone())
    );
}

#[test]
fn the_relay_reads_the_last_guard_home_flag() {
    let mut args = proxy_args();
    args.extend(strings(&["--guard-home=/second", "--arg=--guard-home"]));
    assert_eq!(proxy_guard_home(&args), Some("/second".into()));
}

#[test]
fn a_frozen_caller_needs_a_guard_home_and_publishes_a_durable_copy() {
    let dir = TempDir::new().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let source = root.join("hol-guard-runtime");
    fs::write(&source, b"abc").unwrap();
    let stamp = json!({
        "path": source,
        "size": 3,
        "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "features": [RELAY_FEATURE],
    });
    let ctx = ctx(true, stamp, json!({}));
    assert_eq!(bridge(&ctx, RELAY_FEATURE, None).unwrap(), None);
    let guard_home = root.join("guard");
    let copy = bridge(&ctx, RELAY_FEATURE, Some(&guard_home))
        .unwrap()
        .unwrap();
    assert_eq!(
        copy,
        guard_home
            .join("native-runtime")
            .join("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .join("hol-guard-runtime")
            .to_string_lossy()
    );
    assert_eq!(fs::read(&copy).unwrap(), b"abc");
}

#[cfg(unix)]
#[test]
fn launcher_env_resolves_the_callers_import_path_and_keeps_its_bindings() {
    let ctx = ctx(
        false,
        Value::Null,
        json!({"PYTHONPATH": " lib : /abs//site/ :~/extra:/abs/site", "HOL_GUARD_NATIVE": "1"}),
    );
    let server = vec![
        ("PYTHONPATH".to_owned(), "/server".to_owned()),
        ("HOL_GUARD_NATIVE".to_owned(), "0".to_owned()),
        ("TOKEN".to_owned(), "t".to_owned()),
    ];
    assert_eq!(
        launcher_env(&ctx, &server),
        vec![
            (
                "PYTHONPATH".to_owned(),
                "/work/lib:/abs/site:/u/home/extra:/server".to_owned()
            ),
            ("TOKEN".to_owned(), "t".to_owned()),
            ("HOL_GUARD_NATIVE".to_owned(), "1".to_owned()),
        ]
    );
    let cleared = launcher_env(&ctx, &[("PYTHONPATH".to_owned(), " ".to_owned())]);
    assert_eq!(cleared[0], ("PYTHONPATH".to_owned(), String::new()));
}
