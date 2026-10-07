use super::*;

fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn plan(adapter: &[&str], execution: &[&str], env_sha: &str, reusable: bool) -> GuardRunLaunchPlan {
    GuardRunLaunchPlan {
        adapter_command: adapter.iter().map(|s| s.to_string()).collect(),
        execution_command: execution.iter().map(|s| s.to_string()).collect(),
        environment: BTreeMap::new(),
        environment_sha256: env_sha.to_string(),
        identity: json!({"argv_sha256": "abc"}),
        launch_cwd: PathBuf::from("/tmp/project"),
        reusable,
    }
}

/// Oracle vectors captured from Python `_guard_run_launch_environment_hash`.
#[test]
fn environment_hash_matches_python_oracle() {
    assert_eq!(
        guard_run_launch_environment_hash(&env(&[])),
        "d866d946d5bf0e19f8c831e62f91883d996b0b88b95725710da750ddf0412ed6"
    );
    assert_eq!(
        guard_run_launch_environment_hash(&env(&[("A", "1")])),
        "5ab9d0ca92a7216d2318a54e6f865596f04fba4b00f3a3b3caff2fb43f889e85"
    );
    assert_eq!(
        guard_run_launch_environment_hash(&env(&[("B", "2"), ("A", "1"), ("Z", "3")])),
        "c4b9ec10b89ae9ae91849397d685c8e65c41e7c77d9c265d5aa17b3e08462815"
    );
    assert_eq!(
        guard_run_launch_environment_hash(&env(&[
            ("HOME", "/tmp/x"),
            ("PATH", "/usr/bin"),
            ("LANG", "en_US.UTF-8"),
            ("X_Ops", "ü")
        ])),
        "8f3f457eff1ea9adf3c9e166c1631911cbdaf57e4f4a689280306e840b14de92"
    );
}

#[test]
fn environment_hash_is_insertion_order_independent() {
    let mut reversed = BTreeMap::new();
    reversed.insert("Z".to_string(), "3".to_string());
    reversed.insert("A".to_string(), "1".to_string());
    reversed.insert("B".to_string(), "2".to_string());
    assert_eq!(
        guard_run_launch_environment_hash(&reversed),
        guard_run_launch_environment_hash(&env(&[("B", "2"), ("A", "1"), ("Z", "3")]))
    );
}

#[test]
fn executable_prefix_recovers_prepended_wrapper() {
    let p = plan(
        &["npm", "install"],
        &["/usr/local/bin/npm", "npm", "install"],
        "sig",
        true,
    );
    assert_eq!(
        guard_run_executable_prefix(&p),
        Some(vec!["/usr/local/bin/npm".to_string()])
    );
}

#[test]
fn executable_prefix_none_when_same_or_shorter_or_mismatched_tail() {
    assert_eq!(
        guard_run_executable_prefix(&plan(&["a"], &["a"], "s", true)),
        None
    );
    assert_eq!(
        guard_run_executable_prefix(&plan(&["a", "b"], &["x", "c", "d"], "s", true)),
        None
    );
}

#[test]
fn plan_signature_none_when_not_reusable() {
    assert_eq!(
        guard_run_launch_plan_signature(&plan(&["a"], &["a"], "s", false)),
        None
    );
}

#[test]
fn plan_signature_reusable_shape() {
    let p = plan(&["npm", "install"], &["npm", "install"], "deadbeef", true);
    let sig = guard_run_launch_plan_signature(&p).unwrap();
    let parsed: Value = serde_json::from_str(&sig).unwrap();
    let obj = parsed.as_object().unwrap();
    assert_eq!(obj.get("adapter_command"), Some(&json!(["npm", "install"])));
    assert_eq!(obj.get("environment_sha256"), Some(&json!("deadbeef")));
    assert_eq!(obj.get("identity"), Some(&json!({"argv_sha256": "abc"})));
    assert!(sig.starts_with("{\"adapter_command\""));
    assert!(!sig.contains(": "));
}

#[test]
fn is_guard_action_canonical_lattice_only() {
    for v in [
        "allow",
        "warn",
        "review",
        "require-reapproval",
        "sandbox-required",
        "block",
    ] {
        assert!(guard_run_is_guard_action(&json!(v)), "{v}");
    }
    for v in ["allow ", "ALLOW", "deny", "", "none"] {
        assert!(!guard_run_is_guard_action(&json!(v)), "{v}");
    }
    assert!(!guard_run_is_guard_action(&json!(1)));
    assert!(!guard_run_is_guard_action(&Value::Null));
}
