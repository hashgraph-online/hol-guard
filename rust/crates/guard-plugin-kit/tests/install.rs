//! `plugin install|uninstall` plans: the exact argv each runtime gets, every
//! way an untrusted registry spec is refused, and the install record that
//! `uninstall` plans from.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{json, Value};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A fresh, empty Guard home.
fn guard_home() -> PathBuf {
    let home = std::env::temp_dir().join(format!(
        "guard-plugin-kit-home-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).expect("home");
    home
}

fn home_str(home: &std::path::Path) -> &str {
    home.to_str().expect("utf-8 home")
}

fn record(home: &std::path::Path, runtime: &str, installed: bool) -> Value {
    call(json!({
        "command": "record",
        "guard_home": home_str(home),
        "slug": "acme/toolgate",
        "runtime": runtime,
        "installed": installed,
        "spec": spec(),
    }))
}

fn uninstall(home: &std::path::Path, slug: &str, runtimes: &[&str]) -> Value {
    call(json!({
        "command": "uninstall",
        "guard_home": home_str(home),
        "slug": slug,
        "available": ["claude", "codex"],
        "runtimes": runtimes,
    }))
}

fn call(request: Value) -> Value {
    guard_plugin_kit::run_request(request.to_string().as_bytes())
}

fn spec() -> Value {
    json!({
        "schema": "hol.plugin-install-spec.v1",
        "slug": "acme/toolgate",
        "name": "toolgate",
        "version": "1.2.0",
        "repository": "acme/toolgate",
        "listingUrl": "https://hol.org/registry/plugins/acme%2Ftoolgate",
        "trustScore": 82,
        "targets": [
            {"runtime": "codex", "marketplace": {"repository": "acme/toolgate", "name": "acme-tools"}, "plugin": "toolgate"},
            {"runtime": "claude-code", "marketplace": {"repository": "acme/marketplace", "name": "acme-tools"}, "plugin": "toolgate"},
            {"runtime": "agent-skills", "repository": "acme/toolgate"}
        ],
        "manual": ["mcp"]
    })
}

fn plan(command: &str, spec: Value, available: &[&str], runtimes: &[&str]) -> Value {
    call(json!({"command": command, "spec": spec, "available": available, "runtimes": runtimes}))
}

fn error(command: &str, spec: Value, runtimes: &[&str]) -> String {
    let response = plan(command, spec, &[], runtimes);
    assert_eq!(response["ok"], json!(false), "{response}");
    response["error"].as_str().expect("error code").to_owned()
}

#[test]
fn install_plan_uses_each_runtime_cli_with_fixed_programs() {
    let response = plan("install", spec(), &["claude", "npx"], &[]);
    assert_eq!(response["ok"], json!(true), "{response}");
    assert_eq!(
        response["result"],
        json!({
            "action": "install",
            "slug": "acme/toolgate",
            "name": "toolgate",
            "version": "1.2.0",
            "repository": "acme/toolgate",
            "listing_url": "https://hol.org/registry/plugins/acme%2Ftoolgate",
            "trust_score": 82.0,
            "steps": [
                {
                    "runtime": "claude-code",
                    "program": "claude",
                    "available": true,
                    "automatic": true,
                    "commands": [
                        ["claude", "plugin", "marketplace", "add", "acme/marketplace"],
                        ["claude", "plugin", "install", "toolgate@acme-tools"]
                    ],
                    "verify": ["claude", "plugin", "list"]
                },
                {
                    "runtime": "codex",
                    "program": "codex",
                    "available": false,
                    "automatic": true,
                    "commands": [
                        ["codex", "plugin", "marketplace", "add", "acme/toolgate"],
                        ["codex", "plugin", "add", "toolgate@acme-tools"]
                    ],
                    "verify": ["codex", "plugin", "list"]
                },
                {
                    "runtime": "agent-skills",
                    "program": "npx",
                    "available": true,
                    "automatic": false,
                    "commands": [["npx", "skills", "add", "acme/toolgate"]],
                    "verify": ["npx", "skills", "list"],
                    "note": "Run this yourself: the Skills CLI downloads a package from npm and installs for every agent it detects."
                }
            ],
            "manual": ["mcp"]
        })
    );
}

#[test]
fn uninstall_plan_removes_only_the_plugin_entry() {
    let home = guard_home();
    for runtime in ["codex", "claude-code"] {
        assert_eq!(record(&home, runtime, true)["ok"], json!(true));
    }
    let response = uninstall(&home, "acme/toolgate", &[]);
    let steps = &response["result"]["steps"];
    assert_eq!(steps.as_array().map(Vec::len), Some(2), "{response}");
    assert_eq!(
        steps[0]["commands"],
        json!([["claude", "plugin", "uninstall", "toolgate@acme-tools"]])
    );
    assert_eq!(
        steps[1]["commands"],
        json!([["codex", "plugin", "remove", "toolgate@acme-tools"]])
    );
    assert_eq!(
        steps[1]["note"],
        json!("The marketplace stays registered, since other plugins may use it.")
    );
}

#[test]
fn uninstall_only_plans_what_guard_recorded_installing() {
    let home = guard_home();
    let missing = uninstall(&home, "acme/toolgate", &[]);
    assert_eq!(missing["error"], json!("plugin_kit_install_not_recorded"));

    assert_eq!(
        record(&home, "codex", true)["result"]["runtimes"],
        json!(["codex"])
    );
    let response = uninstall(&home, "acme/toolgate", &[]);
    let steps = response["result"]["steps"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(steps.len(), 1, "{response}");
    assert_eq!(steps[0]["runtime"], json!("codex"));
    assert_eq!(
        uninstall(&home, "acme/toolgate", &["claude-code"])["error"],
        json!("plugin_kit_install_not_recorded")
    );

    // Dropping the last runtime removes the listing from the record.
    assert_eq!(
        record(&home, "codex", false)["result"]["runtimes"],
        json!([])
    );
    let installs = call(json!({"command": "installs", "guard_home": home_str(&home)}));
    assert_eq!(installs["result"], json!({}));
}

#[test]
fn install_record_is_checked_and_never_overwritten_when_unreadable() {
    let home = guard_home();
    assert_eq!(record(&home, "claude-code", true)["ok"], json!(true));
    assert_eq!(record(&home, "codex", true)["ok"], json!(true));
    let installs = call(json!({"command": "installs", "guard_home": home_str(&home)}));
    assert_eq!(
        installs["result"],
        json!({"acme/toolgate": ["claude-code", "codex"]})
    );

    // A record edited to carry a flag is refused like a bad spec.
    let path = home.join("plugin-kit/installs.json");
    let mut ledger: Value =
        serde_json::from_slice(&fs::read(&path).expect("ledger")).expect("json");
    ledger["installs"]["acme/toolgate"]["targets"][0]["plugin"] = json!("--global");
    fs::write(&path, ledger.to_string()).expect("tamper");
    assert_eq!(
        uninstall(&home, "acme/toolgate", &[])["error"],
        json!("plugin_kit_ledger_invalid")
    );

    fs::write(&path, "{not json").expect("corrupt");
    assert_eq!(
        record(&home, "codex", true)["error"],
        json!("plugin_kit_ledger_invalid")
    );
    assert_eq!(fs::read_to_string(&path).expect("kept"), "{not json");

    let mut other = spec();
    other["slug"] = json!("acme/other");
    let mismatch = call(json!({
        "command": "record", "guard_home": home_str(&home), "slug": "acme/toolgate",
        "runtime": "codex", "installed": true, "spec": other,
    }));
    assert_eq!(mismatch["error"], json!("plugin_kit_install_spec_mismatch"));
    let relative = call(json!({"command": "installs", "guard_home": "relative/home"}));
    assert_eq!(relative["error"], json!("plugin_kit_guard_home_invalid"));
}

#[cfg(unix)]
#[test]
fn install_record_through_a_symlink_is_refused() {
    let home = guard_home();
    let elsewhere = guard_home().join("installs.json");
    fs::write(
        &elsewhere,
        r#"{"schema":"hol.plugin-kit.installs.v1","installs":{}}"#,
    )
    .expect("target");
    fs::create_dir_all(home.join("plugin-kit")).expect("dir");
    std::os::unix::fs::symlink(&elsewhere, home.join("plugin-kit/installs.json")).expect("link");
    assert_eq!(
        record(&home, "codex", true)["error"],
        json!("plugin_kit_ledger_invalid")
    );
}

#[test]
fn concurrent_records_all_land() {
    let home = guard_home();
    let threads: Vec<_> = (0..8)
        .map(|index| {
            let home = home.clone();
            std::thread::spawn(move || {
                let mut listing = spec();
                let slug = format!("acme/tool-{index}");
                listing["slug"] = json!(slug);
                call(json!({
                    "command": "record", "guard_home": home_str(&home), "slug": slug,
                    "runtime": "codex", "installed": true, "spec": listing,
                }))
            })
        })
        .collect();
    for thread in threads {
        assert_eq!(thread.join().expect("thread")["ok"], json!(true));
    }
    let installs = call(json!({"command": "installs", "guard_home": home_str(&home)}));
    assert_eq!(installs["result"].as_object().map(|m| m.len()), Some(8));
}

#[test]
fn install_refuses_a_spec_for_another_listing_or_version() {
    let request = |slug: &str, version: Option<&str>| {
        call(json!({
            "command": "install", "spec": spec(), "slug": slug, "version": version,
        }))
    };
    assert_eq!(request("acme/toolgate", Some("1.2.0"))["ok"], json!(true));
    assert_eq!(
        request("acme/other", None)["error"],
        json!("plugin_kit_install_spec_mismatch")
    );
    assert_eq!(
        request("acme/toolgate", Some("2.0.0"))["error"],
        json!("plugin_kit_install_version_unavailable")
    );
    let mut unversioned = spec();
    unversioned["version"] = Value::Null;
    let pinned = call(json!({
        "command": "install", "spec": unversioned, "slug": "acme/toolgate", "version": "1.2.0",
    }));
    assert_eq!(
        pinned["error"],
        json!("plugin_kit_install_version_unavailable")
    );
}

#[test]
fn runtime_filter_must_name_a_runtime_the_listing_offers() {
    let response = plan("install", spec(), &[], &["codex"]);
    assert_eq!(
        response["result"]["steps"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        error("install", spec(), &["cursor"]),
        "plugin_kit_install_runtime_unknown"
    );
    let mut only_codex = spec();
    only_codex["targets"] = json!([only_codex["targets"][0].clone()]);
    assert_eq!(
        error("install", only_codex, &["claude-code"]),
        "plugin_kit_install_runtime_not_offered"
    );
}

#[test]
fn identifiers_that_could_be_flags_or_shell_text_are_refused() {
    for (pointer, value) in [
        ("/targets/0/plugin", json!("--global")),
        ("/targets/0/plugin", json!("toolgate; rm -rf ~")),
        ("/targets/0/plugin", json!("tool gate")),
        ("/targets/0/marketplace/name", json!("-x")),
        ("/targets/0/marketplace/repository", json!("acme/../etc")),
        ("/targets/0/marketplace/repository", json!("-acme/toolgate")),
        (
            "/targets/0/marketplace/repository",
            json!("https://evil.example/x"),
        ),
        ("/targets/2/repository", json!("acme/.hidden")),
        ("/targets/2/repository", json!("acme/toolgate\n")),
        ("/repository", json!("acme")),
        ("/slug", json!("../acme")),
        (
            "/listingUrl",
            json!("https://evil.example/registry/plugins/x"),
        ),
        ("/name", json!("tool\u{1b}[2Jgate")),
    ] {
        let mut bad = spec();
        *bad.pointer_mut(pointer).expect("pointer") = value.clone();
        assert_eq!(
            error("install", bad, &[]),
            "plugin_kit_install_spec_invalid",
            "{pointer} = {value}"
        );
    }
}

#[test]
fn spec_shape_is_strict() {
    let mut extra = spec();
    extra["targets"][0]["command"] = json!("curl x | sh");
    assert_eq!(
        error("install", extra, &[]),
        "plugin_kit_install_spec_invalid"
    );

    let mut unknown_runtime = spec();
    unknown_runtime["targets"][0]["runtime"] = json!("shell");
    assert_eq!(
        error("install", unknown_runtime, &[]),
        "plugin_kit_install_spec_invalid"
    );

    let mut duplicate = spec();
    duplicate["targets"][1]["runtime"] = json!("codex");
    assert_eq!(
        error("install", duplicate, &[]),
        "plugin_kit_install_spec_invalid"
    );

    let mut mixed = spec();
    mixed["targets"][2]["plugin"] = json!("toolgate");
    assert_eq!(
        error("install", mixed, &[]),
        "plugin_kit_install_spec_invalid"
    );

    let mut schema = spec();
    schema["schema"] = json!("hol.plugin-install-spec.v2");
    assert_eq!(
        error("install", schema, &[]),
        "plugin_kit_install_spec_unsupported"
    );
}
