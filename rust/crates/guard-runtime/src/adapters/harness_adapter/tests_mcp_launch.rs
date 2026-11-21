//! The launcher selection of Guard-managed MCP stdio proxies, ported from
//! `tests/test_mcp_relay_native_launch.py`: the native relay when the validated
//! runtime advertises it, the Python proxy otherwise.

use std::fs;

use serde_json::{json, Map, Value};
use tempfile::TempDir;

use super::files::render;
use super::proxy_launch::{entry, python_launch, relay_launch, RELAY_FEATURE};
use super::Ctx;
use crate::mcp_relay::{RELAY_COMMAND, RELAY_FEATURE as NATIVE_RELAY_FEATURE};
use crate::pyjson::PyVal;

const RUNTIME: &str = "/opt/guard/hol-guard-runtime";
const ARGS_SOURCE: &str = include_str!("../../mcp_relay_args.rs");
const PROXIES: [&str; 6] = [
    "cline-mcp-proxy",
    "codex-mcp-proxy",
    "copilot-mcp-proxy",
    "cursor-mcp-proxy",
    "hermes-mcp-proxy",
    "opencode-mcp-proxy",
];

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn stamp(features: &[&str]) -> Value {
    json!({"path": RUNTIME, "size": 0, "sha256": "0".repeat(64), "features": features})
}

fn ctx(frozen: bool, native_runtime: Value, guard_home: &str) -> Ctx {
    Ctx::parse(Some(&json!({
        "home": "/u/home",
        "workspace": null,
        "guard_home": guard_home,
        "home_override_explicit": false,
        "cwd": "/work",
        "user_home": "/u/home",
        "env": {},
        "caller": {
            "executable": "/venv/bin/python",
            "executable_resolved": "/venv/bin/python3.12",
            "frozen": frozen,
            "launcher": "/venv/bin/python",
            "package_root": "/site",
            "version": "1.0.0",
            "native_runtime": native_runtime,
        },
    })))
    .expect("context")
}

fn module_args(proxy: &str) -> Vec<String> {
    strings(&[
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        proxy,
        "--guard-home",
        "/u/home/.hol-guard",
        "--server-name",
        "fixture",
    ])
}

#[test]
fn the_feature_and_proxy_names_match_the_native_relay() {
    assert_eq!(RELAY_FEATURE, NATIVE_RELAY_FEATURE);
    let mut found: Vec<&str> = ARGS_SOURCE
        .lines()
        .filter_map(|line| line.trim().strip_prefix("(\""))
        .filter_map(|line| line.split_once("\", \""))
        .map(|(proxy, _)| proxy)
        .filter(|proxy| proxy.ends_with("-mcp-proxy"))
        .collect();
    found.sort_unstable();
    assert_eq!(found, PROXIES);
}

#[test]
fn an_unadvertised_relay_keeps_the_python_proxy() {
    let ctx = ctx(false, stamp(&["mcp-relay-decide-v2"]), "/g");
    let args = module_args("codex-mcp-proxy");
    assert_eq!(
        relay_launch(&ctx, "/venv/bin/python", &args).expect("launch"),
        ("/venv/bin/python".to_owned(), args)
    );
}

#[test]
fn an_advertised_relay_wraps_the_unchanged_python_argv() {
    let ctx = ctx(false, stamp(&[RELAY_FEATURE]), "/g");
    for proxy in PROXIES {
        let args = module_args(proxy);
        let (command, launch) = relay_launch(&ctx, "/venv/bin/python", &args).expect("launch");
        assert_eq!(command, RUNTIME);
        let mut expected = strings(&[RELAY_COMMAND, "/venv/bin/python"]);
        expected.extend(args.clone());
        assert_eq!(launch, expected);
        // The relay finds `guard <proxy>` in its argv exactly as in the Python launch.
        let guard = launch.iter().position(|arg| arg == "guard").expect("guard");
        assert_eq!(launch[guard + 1], proxy);
        assert_eq!(
            python_launch(Some(&command), &launch),
            (Some("/venv/bin/python".to_owned()), args)
        );
    }
}

#[test]
fn other_guard_proxies_are_never_relayed() {
    let ctx = ctx(false, stamp(&[RELAY_FEATURE]), "/g");
    let other = module_args("mcp-proxy");
    assert_eq!(
        relay_launch(&ctx, "/venv/bin/python", &other).expect("launch"),
        ("/venv/bin/python".to_owned(), other.clone())
    );
    assert_eq!(python_launch(Some("/venv/bin/python"), &other).1, other);
    let foreign = strings(&["-m", "other.module", "guard", "codex-mcp-proxy"]);
    assert_eq!(
        relay_launch(&ctx, "/venv/bin/python", &foreign)
            .expect("launch")
            .0,
        "/venv/bin/python"
    );
}

#[test]
fn a_frozen_opencode_argv_relays_in_module_form() {
    let dir = TempDir::new().expect("temp dir");
    let root = fs::canonicalize(dir.path()).expect("root");
    let source = root.join("hol-guard-runtime");
    fs::write(&source, b"abc").expect("runtime");
    let runtime = json!({
        "path": source,
        "size": 3,
        "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "features": [RELAY_FEATURE],
    });
    let guard_home = root.join("guard").to_string_lossy().into_owned();
    let module = strings(&[
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "opencode-mcp-proxy",
        "--guard-home",
        &guard_home,
    ]);
    let frozen_args = module[3..].to_vec();
    let launcher = "/u/bin/hol-guard";
    // A source caller never relays a CLI argv that names the proxy directly.
    let source_ctx = ctx(false, runtime.clone(), &guard_home);
    assert_eq!(
        relay_launch(&source_ctx, launcher, &frozen_args).expect("launch"),
        (launcher.to_owned(), frozen_args.clone())
    );
    let frozen = ctx(true, runtime, &guard_home);
    let (command, launch) = relay_launch(&frozen, launcher, &frozen_args).expect("launch");
    let copy = root
        .join("guard")
        .join("native-runtime")
        .join("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        .join("hol-guard-runtime");
    assert_eq!(command, copy.to_string_lossy());
    let mut expected = strings(&[RELAY_COMMAND, launcher]);
    expected.extend(module.clone());
    assert_eq!(launch, expected);
    assert_eq!(
        python_launch(Some(&command), &launch),
        (Some(launcher.to_owned()), module)
    );
    let scan = strings(&["scan", "--guard-home", "x"]);
    assert_eq!(
        relay_launch(&frozen, launcher, &scan).expect("launch"),
        (launcher.to_owned(), scan)
    );
}

fn fixture_server() -> Map<String, Value> {
    match json!({
        "harness": "codex",
        "name": "fixture",
        "source_scope": "user",
        "config_path": "/u/home/config.toml",
        "command": "python",
        "args": ["fixture_server.py", "--stdio"],
        "transport": "stdio",
        "env": [],
    }) {
        Value::Object(server) => server,
        _ => unreachable!("the fixture server is an object"),
    }
}

fn launched(ctx: &Ctx) -> Value {
    let launch = entry(ctx, "codex-mcp-proxy", &fixture_server()).expect("entry");
    let rendered = render(&PyVal::Dict(launch)).expect("render");
    serde_json::from_str(&rendered).expect("entry json")
}

#[test]
fn the_shared_launcher_entry_selects_the_relay() {
    let python = launched(&ctx(false, Value::Null, "/u/home/.hol-guard"));
    assert_eq!(python["command"], "/venv/bin/python");
    let relayed = launched(&ctx(false, stamp(&[RELAY_FEATURE]), "/u/home/.hol-guard"));
    assert_eq!(relayed["command"], RUNTIME);
    let mut expected = vec![json!(RELAY_COMMAND), json!("/venv/bin/python")];
    expected.extend(python["args"].as_array().expect("args").clone());
    assert_eq!(relayed["args"], Value::Array(expected));
    assert_eq!(python["args"][3], "codex-mcp-proxy");
}

#[test]
fn a_launch_that_carries_no_proxy_is_not_unwrapped() {
    let launch = strings(&[RELAY_COMMAND, "/venv/bin/python"]);
    assert_eq!(
        python_launch(Some(RUNTIME), &launch),
        (Some(RUNTIME.to_owned()), launch)
    );
}
