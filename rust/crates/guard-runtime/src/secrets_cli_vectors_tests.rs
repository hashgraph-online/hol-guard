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

#[test]
fn detector_version_and_rule_catalog_match_python() {
    let vectors = vectors();
    assert_eq!(vectors["detector_version"], detector_version());
    assert_eq!(vectors["rules"]["detector_version"], detector_version());
    let recorded = vectors["rules"]["rules"].as_array().unwrap();
    let catalog = secret_rule_catalog();
    assert_eq!(recorded.len(), catalog.len());
    for (expected, rule) in recorded.iter().zip(catalog) {
        assert_eq!(expected["rule_id"], rule.rule_id);
        assert_eq!(expected["family"], rule.family, "{}", rule.rule_id);
        assert_eq!(expected["severity"], rule.severity, "{}", rule.rule_id);
        assert_eq!(expected["validation"], rule.validation, "{}", rule.rule_id);
        assert_eq!(
            expected["description"], rule.description,
            "{}",
            rule.rule_id
        );
        // The public catalog omits `strong_format` when it is false.
        let strong = expected.get("strong_format").and_then(Value::as_bool);
        assert_eq!(
            strong.unwrap_or(false),
            rule.strong_format,
            "{}",
            rule.rule_id
        );
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
        assert_eq!(actual, case["expected"], "text vector at {path:?}");
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
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
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
            assert_eq!(actual, case["expected"], "vector {name}");
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
            br#"{"command":"rules"}"#,
            b"not json",
        ] {
            assert_eq!(
                run_command(body).unwrap_err(),
                "secrets_cli_request_invalid"
            );
        }
    }
}
