//! Replays Gemini, Antigravity, Devin, Grok, Kimi, OpenCode and Cursor detection
//! vectors recorded from the original Python implementation (see
//! `testdata/gemini/record_adapter_vectors.py`).
//! Fixture trees and expected artifacts, paths and warnings come from Python,
//! never from Rust output. `<ROOT>` is the fixture root.

use serde_json::{json, Value};

use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::pi_vectors_tests::{materialize, release, substitute};
use crate::runner_authority_op::KindResult;

const GEMINI: &str = include_str!("../../testdata/gemini/vectors.json");
const ANTIGRAVITY: &str = include_str!("../../testdata/antigravity/vectors.json");
const DEVIN: &str = include_str!("../../testdata/devin/vectors.json");
const GROK: &str = include_str!("../../testdata/grok/vectors.json");
const KIMI: &str = include_str!("../../testdata/kimi/vectors.json");
const OPENCODE: &str = include_str!("../../testdata/opencode/vectors.json");
const CURSOR: &str = include_str!("../../testdata/cursor/vectors.json");

fn check(case: &Value, name: &str, root_text: &str, result: KindResult) -> Result<(), String> {
    if case["refused"] == true {
        return match result {
            Err(_) => Ok(()),
            Ok(answer) => Err(format!(
                "{name}: expected a refusal, the resident answered {answer}"
            )),
        };
    }
    let answer = result.map_err(|code| format!("{name}: resident refused with {code}"))?;
    let mismatches: Vec<String> = ["artifacts", "found_paths", "warnings"]
        .into_iter()
        .filter_map(|field| {
            let expected = substitute(&case[field], root_text);
            (answer[field] != expected).then(|| {
                format!(
                    "{name}: {field}\n  resident: {}\n  python:   {expected}",
                    answer[field]
                )
            })
        })
        .collect();
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(mismatches.join("\n"))
    }
}

fn replay_all(vectors: &str, schema: &str, detect: fn(&Value) -> KindResult) {
    let vectors: Value = serde_json::from_str(vectors).unwrap();
    assert_eq!(vectors["schema"], schema);
    let mut replayed = 0;
    let mut failures = Vec::new();
    for case in vectors["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let root = temp_home(&format!("ad-{name}").chars().take(60).collect::<String>());
        materialize(&root, case);
        let root_text = root.to_string_lossy().into_owned();
        let result = detect(&substitute(&case["args"], &root_text));
        if let Err(message) = check(case, name, &root_text, result) {
            failures.push(message);
        }
        release(&root);
        replayed += 1;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(replayed >= 25, "only {replayed} cases recorded");
}

#[test]
fn replays_every_recorded_gemini_detection_case() {
    replay_all(
        GEMINI,
        "guard-gemini-vectors.v1",
        crate::gemini_detect::detect,
    );
}

#[test]
fn replays_every_recorded_antigravity_detection_case() {
    replay_all(
        ANTIGRAVITY,
        "guard-antigravity-vectors.v1",
        crate::antigravity_detect::detect,
    );
}

#[test]
fn replays_every_recorded_grok_detection_case() {
    replay_all(GROK, "guard-grok-vectors.v1", crate::grok_detect::detect);
}

#[test]
fn replays_every_recorded_kimi_detection_case() {
    replay_all(KIMI, "guard-kimi-vectors.v1", crate::kimi_detect::detect);
}

#[test]
fn replays_every_recorded_opencode_detection_case() {
    replay_all(
        OPENCODE,
        "guard-opencode-vectors.v1",
        crate::opencode_detect::detect,
    );
}

#[test]
fn replays_every_recorded_cursor_detection_case() {
    replay_all(
        CURSOR,
        "guard-cursor-vectors.v1",
        crate::cursor_detect::detect,
    );
}

fn valid_request(harness: &str) -> Value {
    let mut valid = json!({"harness": harness, "home": "/nonexistent/home", "workspace": null});
    if harness == "grok" {
        valid["grok_home"] = json!("/nonexistent/grok");
        valid["system_policy_paths"] = json!([]);
    }
    if harness == "opencode" || harness == "cursor" {
        valid["configs"] = json!([]);
    }
    if harness == "opencode" {
        valid["skip_verified_mcp_companions"] = json!(true);
        valid["config_dir"] = json!(null);
    }
    valid
}

#[test]
fn malformed_config_lists_are_refused() {
    for (harness, detect) in [
        (
            "opencode",
            crate::opencode_detect::detect as fn(&Value) -> KindResult,
        ),
        ("cursor", crate::cursor_detect::detect),
    ] {
        for configs in [
            json!(null),
            json!({}),
            json!([{"path": "/x/c.json"}]),
            json!([{"path": 1, "payload": "{}", "scope": "global"}]),
            json!([{"path": "/x\u{0}", "payload": "{}", "scope": "global"}]),
            json!([{"path": "/x/c.json", "payload": "{nope", "scope": "global"}]),
        ] {
            let mut args = valid_request(harness);
            args["configs"] = configs.clone();
            assert!(detect(&args).is_err(), "{harness} configs={configs}");
        }
    }
    let mut args = valid_request("opencode");
    args["skip_verified_mcp_companions"] = json!("yes");
    assert!(crate::opencode_detect::detect(&args).is_err());
}

#[test]
fn malformed_requests_are_refused() {
    for (harness, detect) in [
        (
            "gemini",
            crate::gemini_detect::detect as fn(&Value) -> KindResult,
        ),
        ("antigravity", crate::antigravity_detect::detect),
        ("grok", crate::grok_detect::detect),
        ("kimi", crate::kimi_detect::detect),
        ("opencode", crate::opencode_detect::detect),
        ("cursor", crate::cursor_detect::detect),
    ] {
        let valid = valid_request(harness);
        assert!(detect(&valid).is_ok(), "{harness}");
        for (key, value) in [
            ("harness", json!("claude-code")),
            ("harness", json!(1)),
            ("home", json!(null)),
            ("home", json!("/x\u{0}y")),
            ("workspace", json!(1)),
            ("cwd", json!("relative")),
            ("cwd", json!(1)),
        ] {
            let mut args = valid.clone();
            args[key] = value.clone();
            assert!(detect(&args).is_err(), "{harness} {key}={value}");
        }
        let mut relative = valid.clone();
        relative["home"] = json!("home");
        assert!(
            detect(&relative).is_err(),
            "{harness}: a relative home needs cwd"
        );
        assert!(detect(&json!([])).is_err());
    }
}

#[test]
fn replays_every_recorded_devin_detection_case() {
    replay_all(DEVIN, "guard-devin-vectors.v1", crate::devin_detect::detect);
}

#[test]
fn malformed_devin_requests_are_refused() {
    let valid = json!({
        "harness": "devin",
        "home": "/nonexistent/home",
        "workspace": null,
        "config_dir": "/nonexistent/home/.config/devin",
    });
    assert!(crate::devin_detect::detect(&valid).is_ok());
    for value in [json!(null), json!(1), json!("/x\u{0}y"), json!("relative")] {
        let mut args = valid.clone();
        args["config_dir"] = value.clone();
        assert!(
            crate::devin_detect::detect(&args).is_err(),
            "config_dir={value}"
        );
    }
    let mut args = valid.clone();
    args.as_object_mut().unwrap().remove("config_dir");
    assert!(crate::devin_detect::detect(&args).is_err());
}

/// Python binds a lone surrogate in a configured environment value to an
/// unbound placeholder digest; the resident refuses the inventory instead.
#[test]
fn devin_lone_surrogate_env_value_is_refused() {
    let root = temp_home("ad-devin-env-surrogate");
    let config = root.join("home/.config/devin");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join("mcp_config.json"),
        r#"{"mcpServers": {"s": {"command": "c", "env": {"K": "\udc80"}}}}"#,
    )
    .unwrap();
    let home = root.join("home");
    let result = crate::devin_detect::detect(&json!({
        "harness": "devin",
        "home": home.to_string_lossy(),
        "workspace": null,
        "config_dir": config.to_string_lossy(),
    }));
    release(&root);
    assert!(result.is_err());
}

#[test]
fn malformed_grok_fields_are_refused() {
    let detect = crate::grok_detect::detect;
    let valid = valid_request("grok");
    assert!(detect(&valid).is_ok());
    for (key, value) in [
        ("grok_home", json!(null)),
        ("grok_home", json!(1)),
        ("grok_home", json!("/x\u{0}y")),
        ("grok_home", json!("relative")),
        ("system_policy_paths", json!(null)),
        (
            "system_policy_paths",
            json!("/etc/grok/managed_config.toml"),
        ),
        ("system_policy_paths", json!([1])),
        ("system_policy_paths", json!(["relative.toml"])),
        ("system_policy_paths", json!(["/x\u{0}y"])),
    ] {
        let mut args = valid.clone();
        args[key] = value.clone();
        assert!(detect(&args).is_err(), "grok {key}={value}");
    }
    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("grok_home");
    assert!(detect(&missing).is_err(), "grok_home is required");
    let mut missing = valid.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("system_policy_paths");
    assert!(detect(&missing).is_err(), "system_policy_paths is required");
    let mut relative = valid.clone();
    relative["grok_home"] = json!("grok");
    relative["cwd"] = json!("/nonexistent");
    assert!(
        detect(&relative).is_ok(),
        "a relative grok_home reads from cwd"
    );
}

/// `.gemini/extensions` that cannot be examined is a refusal, not an empty
/// inventory. The link reaches a locked directory, so only the extension root
/// fails its `stat`: `settings.json` and `skills` beside it stay readable.
#[cfg(unix)]
#[test]
fn an_unexaminable_gemini_extension_root_is_refused_not_empty() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "guard-gemini-extension-root-{}-{nonce}",
        std::process::id()
    ));
    let gemini = root.join("home/.gemini");
    let locked = root.join("locked");
    std::fs::create_dir_all(&gemini).unwrap();
    std::fs::create_dir_all(locked.join("extensions")).unwrap();
    let mut args = valid_request("gemini");
    args["home"] = json!(root.join("home").to_string_lossy());
    assert!(crate::gemini_detect::detect(&args).is_ok(), "absent root");
    symlink(locked.join("extensions"), gemini.join("extensions")).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Permission bits do not bind a privileged user, who can still stat it.
    let privileged = std::fs::metadata(gemini.join("extensions")).is_ok();
    let result = crate::gemini_detect::detect(&args);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::remove_dir_all(&root).unwrap();
    if !privileged {
        assert_eq!(
            result.unwrap_err(),
            "native_runner_authority_adapter_path_unexaminable"
        );
    }
}
