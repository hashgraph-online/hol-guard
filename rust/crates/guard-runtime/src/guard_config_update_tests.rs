use super::*;

/// Recorded from the Python writer in `guard/config.py` before the port.
const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/fixtures/guard_settings_write_parity.json"
));

fn scratch(label: &str) -> PathBuf {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::env::temp_dir().join(format!(
        "hol-guard-config-update-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn replay(fixture: &Value, case: &Value) -> Result<Computed, Failure> {
    let text = fixture["texts"][case["text"].as_str().unwrap()].as_str();
    let value = pyjson::parse(case["payload_text"].as_str().unwrap()).unwrap();
    let managed: Option<ManagedInput> = (!case["managed"].is_null())
        .then(|| serde_json::from_value(case["managed"].clone()).unwrap());
    compute(
        case["kind"].as_str().unwrap(),
        text,
        &value,
        managed.as_ref(),
        case["cloud_sync_entitled"].as_bool().unwrap(),
        fixture["now"].as_str().unwrap(),
    )
}

fn mismatch(case: &Value, outcome: &Result<Computed, Failure>) -> Option<String> {
    let label = format!("{} {} {}", case["kind"], case["text"], case["payload_text"]);
    match (outcome, case.get("written")) {
        // A written file whose reload failed (the old writer's surrogate
        // escapes) still has to be byte-identical.
        (Ok(computed), Some(written)) => {
            if computed.text != written.as_str().unwrap() {
                return Some(format!(
                    "{label}: wrote {:?}, expected {written}",
                    computed.text
                ));
            }
            match (&computed.previous, case.get("previous")) {
                (Some(previous), Some(expected)) if previous != expected => {
                    Some(format!("{label}: previous {previous}, expected {expected}"))
                }
                _ => None,
            }
        }
        (Err(Failure::Invalid(message)), None)
            if case["error"].as_str() == Some(message.as_str()) =>
        {
            None
        }
        (Ok(computed), None) => Some(format!(
            "{label}: wrote {:?}, expected error {}",
            computed.text, case["error"]
        )),
        (Err(failure), _) => Some(format!("{label}: {failure:?}, expected {case}")),
    }
}

#[test]
fn python_parity_vectors_match() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() > 1_500);
    let mismatches: Vec<String> = cases
        .iter()
        .filter_map(|case| mismatch(case, &replay(&fixture, case)))
        .collect();
    assert!(
        mismatches.is_empty(),
        "{} of {} vectors differ:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches
            .iter()
            .take(25)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

fn run(home: &Path, kind: &str, value_text: &str) -> Value {
    let request = json!({
        "schema": SCHEMA,
        "guard_home": home,
        "kind": kind,
        "value_text": value_text,
        "managed": null,
        "cloud_sync_entitled": false,
    });
    let response = run_command(request.to_string().as_bytes()).unwrap();
    serde_json::from_slice(&response).unwrap()
}

#[test]
fn command_writes_creates_and_resets_home_config() {
    let home = scratch("command").join("home");
    let response = run(
        &home,
        "settings",
        r#"{"mode": "enforce", "telemetry": true}"#,
    );
    assert_eq!(response["ok"], json!(true));
    assert_eq!(response["previous"]["previous"], json!("protected"));
    let config = home.join(HOME_CONFIG_FILENAME);
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        "mode = \"enforce\"\ntelemetry = true\n"
    );

    let response = run(&home, "channel", r#""alpha""#);
    assert_eq!(response, json!({"ok": true, "previous": null}));
    assert!(fs::read_to_string(&config)
        .unwrap()
        .contains("update_channel = \"alpha\""));

    assert_eq!(run(&home, "reset", "null")["ok"], json!(true));
    assert_eq!(fs::read_to_string(&config).unwrap(), "\n");
}

#[test]
fn command_reports_invalid_payloads_without_writing() {
    let home = scratch("invalid").join("home");
    let response = run(&home, "channel", r#""nightly""#);
    assert_eq!(
        response,
        json!({"ok": false, "invalid": "Update channel must be stable or alpha."})
    );
    assert!(!home.exists());

    let response = run(&home, "settings", r#"{"mode": "loud"}"#);
    assert_eq!(response["invalid"], json!("Invalid Guard mode."));
    assert!(!home.join(HOME_CONFIG_FILENAME).exists());
}

#[test]
fn command_refuses_untrusted_or_malformed_config() {
    let home = scratch("malformed").join("home");
    fs::create_dir_all(&home).unwrap();
    fs::write(home.join(HOME_CONFIG_FILENAME), "mode = [").unwrap();
    let response = run(&home, "reset", "null");
    assert_eq!(response, json!({"ok": false, "error": "config_malformed"}));
    assert_eq!(
        fs::read_to_string(home.join(HOME_CONFIG_FILENAME)).unwrap(),
        "mode = ["
    );
}

#[test]
fn command_rejects_unknown_kinds_and_schemas() {
    let home = scratch("schema").join("home");
    let request = json!({
        "schema": SCHEMA,
        "guard_home": home,
        "kind": "delete",
        "value_text": "null",
    });
    assert!(run_command(request.to_string().as_bytes()).is_err());
    let request = json!({
        "schema": "guard-config-update.v0",
        "guard_home": home,
        "kind": "reset",
        "value_text": "null",
    });
    assert!(run_command(request.to_string().as_bytes()).is_err());
}
