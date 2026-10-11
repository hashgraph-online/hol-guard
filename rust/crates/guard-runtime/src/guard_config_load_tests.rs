use super::*;
use std::fs;

const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/fixtures/guard_config_parity.json"
));

fn scratch(label: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "hol-guard-config-load-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("home")).unwrap();
    fs::create_dir_all(root.join("ws")).unwrap();
    root
}

fn request_for(root: &Path, case: &Value) -> LoadRequest {
    let files = case["files"].as_object().unwrap();
    for (relative, text) in files {
        fs::write(root.join(relative), text.as_str().unwrap()).unwrap();
    }
    let workspace = files
        .keys()
        .any(|key| key.starts_with("ws/"))
        .then(|| root.join("ws"));
    let managed = (!case["managed"].is_null())
        .then(|| serde_json::from_value(case["managed"].clone()).unwrap());
    LoadRequest {
        schema: SCHEMA.to_owned(),
        guard_home: root.join("home"),
        workspace,
        require_canonical_workspace: false,
        managed,
    }
}

#[test]
fn python_parity_vectors_match() {
    let cases: Vec<Value> = serde_json::from_str(FIXTURE).unwrap();
    assert!(cases.len() > 90);
    let mut mismatches = Vec::new();
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let root = scratch("vector");
        let outcome = load(&request_for(&root, case));
        let expected = &case["expected"];
        let matched = match (&outcome, expected.get("config")) {
            (Ok(actual), Some(config)) => actual == config,
            (Err(_), None) => true,
            _ => false,
        };
        if !matched {
            mismatches.push(format!("{name}: expected {expected} got {outcome:?}"));
        }
        let _ = fs::remove_dir_all(root);
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn run_command_reports_load_failure_as_data() {
    let root = scratch("failure");
    fs::write(root.join("home/config.toml"), "mode = = x").unwrap();
    let request = json!({
        "schema": SCHEMA,
        "guard_home": root.join("home"),
    });
    let response = run_command(request.to_string().as_bytes()).unwrap();
    let value: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(value["ok"], json!(false));
    assert_eq!(value["error"], json!("config_malformed"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn run_command_rejects_unknown_fields_and_schema() {
    let root = scratch("invalid");
    let unknown = json!({"schema": SCHEMA, "guard_home": root.join("home"), "extra": 1});
    assert!(run_command(unknown.to_string().as_bytes()).is_err());
    let wrong = json!({"schema": "other", "guard_home": root.join("home")});
    assert!(run_command(wrong.to_string().as_bytes()).is_err());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn missing_home_directory_loads_defaults() {
    let root = scratch("missing");
    let request = LoadRequest {
        schema: SCHEMA.to_owned(),
        guard_home: root.join("absent"),
        workspace: None,
        require_canonical_workspace: false,
        managed: None,
    };
    let config = load(&request).unwrap();
    assert_eq!(config["protection_posture"], json!("protected"));
    assert_eq!(config["mode"], json!("prompt"));
    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn canonical_workspace_rejects_symlinked_ancestors() {
    let root = fs::canonicalize(scratch("symlink")).unwrap();
    fs::create_dir_all(root.join("real/project")).unwrap();
    std::os::unix::fs::symlink(root.join("real"), root.join("alias")).unwrap();
    let request = |workspace: PathBuf| LoadRequest {
        schema: SCHEMA.to_owned(),
        guard_home: root.join("home"),
        workspace: Some(workspace),
        require_canonical_workspace: true,
        managed: None,
    };
    assert!(load(&request(root.join("real/project"))).is_ok());
    assert!(load(&request(root.join("real/absent"))).is_ok());
    assert!(load(&request(root.join("alias/project"))).is_err());
    let mut lenient = request(root.join("alias/project"));
    lenient.require_canonical_workspace = false;
    assert!(load(&lenient).is_ok());
    let _ = fs::remove_dir_all(root);
}
