//! Frozen Desktop uses the same private MAC gate, with all roles pinned to
//! the sidecar bytes rather than to a temporary extracted source tree.
use super::*;

fn fixture() -> Fixture {
    let mut f = Fixture::new();
    let interpreter = f.unsigned["interpreter"].clone();
    let program = interpreter["invocation_path"].as_str().unwrap().to_owned();
    let target = Path::new(interpreter["target"]["path"].as_str().unwrap());
    for file in f.unsigned["packaged_files"].as_array_mut().unwrap() {
        *file = identity(target, file["role"].as_str().unwrap());
    }
    for role in [
        "bridge",
        "bridge_runtime",
        "launch_runtime",
        "runtime_trust",
        "windows_job",
    ] {
        f.unsigned["transport"][role] = f.unsigned["packaged_files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|file| file["role"] == role)
            .unwrap()
            .clone();
    }
    let context = &f.unsigned["context"];
    let fallback = vec![
        program.clone(),
        "hook".into(),
        "--harness".into(),
        "codex".into(),
    ];
    let start = vec![
        program.clone(),
        "--_hol-guard-codex-daemon-recover".into(),
        json!({"guard_home":context["runtime_guard_home"],"home_dir":context["home_dir"]})
            .to_string(),
    ];
    let mut payload: Value = serde_json::from_str(f.argv.last().unwrap()).unwrap();
    payload["fallback_command"] = json!(fallback);
    payload["start_command"] = json!(start);
    let encoded = payload.to_string();
    f.config = super::super::super::parse_config(&encoded).unwrap();
    f.argv = vec![program, "--_hol-guard-codex-bridge".into(), encoded];
    f.unsigned["events"][0]["argv"] = json!(f.argv);
    f.unsigned["fallback"]["argv"] = json!(fallback);
    f.unsigned["daemon_start"]["argv"] = json!(start);
    f.sign();
    f
}

#[test]
fn frozen_sidecar_registration_and_reduced_desktop_budget_are_valid() {
    let f = fixture();
    assert!(f.check());
    let mut child: Value = serde_json::from_str(f.argv.last().unwrap()).unwrap();
    child["hook_timeouts"]["PreToolUse"] = json!(5);
    let encoded = child.to_string();
    let config = super::super::super::parse_config(&encoded).unwrap();
    assert!(authenticate(
        &config,
        &[encoded.clone()],
        Instant::now() + Duration::from_secs(5),
        "PreToolUse"
    )
    .is_some());
    fs::remove_file(&f.manifest).unwrap();
    assert!(authenticate(
        &config,
        &[encoded],
        Instant::now() + Duration::from_secs(5),
        "PreToolUse"
    )
    .is_none());
    assert!(!f.manifest.exists());
    assert!(!Path::new(&f.config.state_path).exists());
}

#[test]
fn frozen_sidecar_cannot_change_recovery_home_or_executable_roles() {
    let mut f = fixture();
    f.config.start_command[2] = json!({"guard_home":"/foreign","home_dir":"/foreign"}).to_string();
    f.unsigned["daemon_start"]["argv"] = json!(f.config.start_command);
    let mut config: Value = serde_json::from_str(f.argv.last().unwrap()).unwrap();
    config["start_command"] = json!(f.config.start_command);
    *f.argv.last_mut().unwrap() = config.to_string();
    f.unsigned["events"][0]["argv"] = json!(f.argv);
    f.sign();
    assert!(!f.check());
    let mut f = fixture();
    f.unsigned["packaged_files"][0]["path"] = json!("/different-runtime");
    f.sign();
    assert!(!f.check());
    let mut f = fixture();
    f.unsigned["events"][0]["argv"][1] = json!("--different-private-command");
    f.sign();
    assert!(!f.check());
}
