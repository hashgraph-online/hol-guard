//! Parity vectors recorded from the Python `guard.secrets` package (see
//! `testdata/secrets_cli/record_secrets_cli_vectors.py`).

use super::*;
use base64ct::{Base64, Encoding};
use guard_scanner::secret_detection::{detector_version, scan_secret_text, secret_rule_catalog};

const VECTORS: &str = include_str!("../testdata/secrets_cli/secrets_cli_vectors.json");
#[cfg(unix)]
const ROOT_TOKEN: &str = "<ROOT>";
/// Inherited repository-location variables (set inside a Git hook) override
/// `git -C`; fixture commands drop them so they never touch the caller's repo.
#[cfg(unix)]
const GIT_LOCATION_ENV: [&str; 6] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_COMMON_DIR",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
];
#[cfg(unix)]
const GIT_ENV: [(&str, &str); 8] = [
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_AUTHOR_NAME", "Guard Test"),
    ("GIT_AUTHOR_EMAIL", "guard@example.invalid"),
    ("GIT_COMMITTER_NAME", "Guard Test"),
    ("GIT_COMMITTER_EMAIL", "guard@example.invalid"),
    ("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z"),
    ("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z"),
];

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn decode(data: &Value) -> Vec<u8> {
    Base64::decode_vec(data.as_str().unwrap()).unwrap()
}

/// The version string the Python detector published for its own rule set.
const PYTHON_DETECTOR_VERSION: &str = "guard-secrets-v1:1d8dc93ef4fc2a04";

/// Rewrite the `detector_version` the recorder captured to the one this build
/// publishes.
///
/// The vectors pin what Python *found*: which rule fires on which line with
/// which score. The digest beside those findings moves whenever a rule is
/// appended, and `guard-scanner` pins its own parity separately by hashing
/// exactly the material Python hashed. Substituting it here keeps the
/// findings comparison meaningful instead of failing every case on one
/// expected string.
fn with_live_detector_version(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| {
                    if key == "detector_version" && item == PYTHON_DETECTOR_VERSION {
                        (key.clone(), Value::String(detector_version()))
                    } else {
                        (key.clone(), with_live_detector_version(item))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(with_live_detector_version).collect()),
        other => other.clone(),
    }
}

#[test]
fn the_rules_command_publishes_the_catalog_python_published() {
    let vectors = vectors();
    let response = respond(&SecretsRequest::Rules(RulesRequest {}));
    assert_eq!(response["ok"], Value::Bool(true));
    // The Python CLI printed a hand-maintained literal. The same bytes now
    // come from the rule table the scan path uses, so what a user reads is
    // what runs: a rule that is renamed, dropped or reordered shows up here.
    let published = vectors["rules"]["rules"].as_array().unwrap();
    let listed = response["result"]["rules"].as_array().unwrap();
    assert_eq!(response["result"]["schema"], vectors["rules"]["schema"]);
    assert_eq!(response["result"]["detector_version"], detector_version());
    // Python's provider rules lead and its synthetic contextual entry stays
    // last, so every entry Python published is still checked exactly; rules
    // added since sit between them.
    let (python_providers, python_contextual) = published.split_at(published.len() - 1);
    assert!(listed.len() > python_providers.len());
    assert_eq!(&listed[..python_providers.len()], python_providers);
    assert_eq!(&listed[listed.len() - 1..], python_contextual);
    let catalog = secret_rule_catalog();
    assert_eq!(listed.len(), catalog.len());
    for (listed, rule) in listed.iter().zip(catalog) {
        assert_eq!(listed["rule_id"], rule.rule_id, "{}", rule.rule_id);
        assert_eq!(listed["family"], rule.family, "{}", rule.rule_id);
        assert_eq!(listed["severity"], rule.severity, "{}", rule.rule_id);
        assert_eq!(listed["validation"], rule.validation, "{}", rule.rule_id);
        assert_eq!(
            listed["strong_format"], rule.strong_format,
            "{}",
            rule.rule_id
        );
        assert_eq!(listed["description"], rule.description, "{}", rule.rule_id);
    }
}

#[test]
fn text_scans_match_python() {
    let vectors = vectors();
    let cases = vectors["text"].as_array().unwrap();
    assert!(cases.len() >= 30);
    for case in cases {
        let text = String::from_utf8(decode(&case["text_b64"])).unwrap();
        let kwargs = &case["kwargs"];
        let path = kwargs.get("path").and_then(Value::as_str).unwrap_or("");
        let source = kwargs
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or("text");
        let commit = kwargs.get("commit").and_then(Value::as_str);
        let max_findings = kwargs
            .get("max_findings")
            .and_then(Value::as_u64)
            .map_or(200, |value| value as usize);
        let summary = scan_secret_text(&text, path, source, commit, max_findings);
        let actual = serde_json::to_value(summary.to_public_dict(None).unwrap()).unwrap();
        assert_eq!(
            actual,
            with_live_detector_version(&case["expected"]),
            "text vector at {path:?}"
        );
    }
}

#[cfg(unix)]
mod cli {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;

    fn temp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "hol-guard-secrets-vec-{name}-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::canonicalize(root).unwrap()
    }

    fn git(root: &Path, args: &[&str]) {
        let mut command = Command::new("git");
        for name in GIT_LOCATION_ENV {
            command.env_remove(name);
        }
        let status = command
            .arg("-C")
            .arg(root)
            .args(args)
            .envs(GIT_ENV)
            .output()
            .unwrap();
        assert!(status.status.success(), "git {args:?}: {status:?}");
    }

    fn request_for(request: &Value, root: &Path) -> SecretsRequest {
        let mut request = request.clone();
        let target = root.join(request["target"].as_str().unwrap());
        request["target"] = Value::String(target.to_str().unwrap().to_owned());
        serde_json::from_value(request).unwrap()
    }

    fn apply(step: &Value, root: &Path) {
        let op = step["op"].as_str().unwrap();
        if op == "git" {
            let args: Vec<&str> = step["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|arg| arg.as_str().unwrap())
                .collect();
            git(root, &args);
            if args.first() == Some(&"init") {
                // The scanner's own Git reads inherit this process's global
                // config; an empty local value masks a developer's global
                // `core.hooksPath` the way the recorder's isolated config did.
                git(root, &["config", "core.hooksPath", ""]);
            }
            return;
        }
        if op == "request" {
            respond(&request_for(&step["request"], root));
            return;
        }
        let path = root.join(step["path"].as_str().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        match op {
            "write_b64" => std::fs::write(&path, decode(&step["data"])).unwrap(),
            "chmod_x" => {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            "symlink" => std::os::unix::fs::symlink(step["to"].as_str().unwrap(), &path).unwrap(),
            other => panic!("unknown vector op {other}"),
        }
    }

    fn normalize(value: Value, root: &str) -> Value {
        match value {
            Value::String(text) => Value::String(text.replace(root, ROOT_TOKEN)),
            Value::Array(items) => Value::Array(
                items
                    .into_iter()
                    .map(|item| normalize(item, root))
                    .collect(),
            ),
            Value::Object(map) => Value::Object(
                map.into_iter()
                    .map(|(key, item)| (key, normalize(item, root)))
                    .collect(),
            ),
            other => other,
        }
    }

    fn hooks_state(root: &Path) -> Value {
        let hooks = root.join(".git/hooks");
        let mut state = serde_json::Map::new();
        let Ok(entries) = std::fs::read_dir(&hooks) else {
            return Value::Object(state);
        };
        let mut entries: Vec<_> = entries.map(|entry| entry.unwrap().path()).collect();
        entries.sort();
        for entry in entries {
            let name = entry.file_name().unwrap().to_str().unwrap().to_owned();
            if name.ends_with(".sample") {
                continue;
            }
            let metadata = std::fs::symlink_metadata(&entry).unwrap();
            let value = if metadata.file_type().is_symlink() {
                json!({"symlink": std::fs::read_link(&entry).unwrap().to_str().unwrap()})
            } else {
                json!({
                    "text": std::fs::read_to_string(&entry).unwrap(),
                    "executable": metadata.permissions().mode() & 0o111 != 0,
                })
            };
            state.insert(name, value);
        }
        Value::Object(state)
    }

    const CUSTOM_HOOKS_PATH_REFUSAL: &str =
        "custom core.hooksPath is configured; HOL Guard will not \
         modify a shared or custom hook directory automatically";

    /// The scanner reads the caller's global Git config, as the Python CLI did.
    /// A developer's global `core.hooksPath` therefore reaches a target that
    /// has no repository-local override, and the refusal is the correct reply.
    fn ambient_hooks_path_configured() -> bool {
        Command::new("git")
            .args(["config", "--global", "--get", "core.hooksPath"])
            .output()
            .is_ok_and(|output| output.status.success() && !output.stdout.trim_ascii().is_empty())
    }

    fn initializes_repository(case: &Value) -> bool {
        case["setup"].as_array().unwrap().iter().any(|step| {
            step["op"] == "git" && step["args"].get(0).and_then(Value::as_str) == Some("init")
        })
    }

    #[test]
    fn cli_requests_match_python() {
        let ambient_hooks_path = ambient_hooks_path_configured();
        let vectors = vectors();
        let cases = vectors["cli"].as_array().unwrap();
        assert!(cases.len() >= 30);
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let root = temp_root(name);
            for step in case["setup"].as_array().unwrap() {
                apply(step, &root);
            }
            let response = respond(&request_for(&case["request"], &root));
            let actual = normalize(response, root.to_str().unwrap());
            let hook_command = case["request"]["command"] != "scan";
            if ambient_hooks_path
                && hook_command
                && !initializes_repository(case)
                && actual["error"] == CUSTOM_HOOKS_PATH_REFUSAL
            {
                let _ = std::fs::remove_dir_all(&root);
                continue;
            }
            assert_eq!(
                actual,
                with_live_detector_version(&case["expected"]),
                "vector {name}"
            );
            if let Some(expected_hooks) = case.get("hooks_after") {
                assert_eq!(&hooks_state(&root), expected_hooks, "hooks for {name}");
            }
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn malformed_requests_are_rejected() {
        for body in [
            &b"{}"[..],
            br#"{"command":"scan","target":".","scope":"everything"}"#,
            br#"{"command":"scan","target":".","scope":"working","extra":1}"#,
            br#"{"command":"rules","target":"."}"#,
            b"not json",
        ] {
            assert_eq!(
                run_command(body).unwrap_err(),
                "secrets_cli_request_invalid"
            );
        }
    }
}
