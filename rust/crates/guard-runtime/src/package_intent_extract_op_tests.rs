use super::*;

use guard_contracts::{PackageIntentParseRequestV1, PackageIntentParseResultV1};
use serde_json::{json, Value};

use crate::package_authority_op::evaluate_package_intent_parse;

fn extract(
    tool_name: Value,
    arguments: Value,
    action_envelope_command: Option<&str>,
) -> PackageIntentParseResultV1 {
    let request = PackageIntentExtractRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        tool_name,
        arguments,
        action_envelope_command: action_envelope_command.map(str::to_owned),
        workspace: None,
        home_dir: None,
        environment: None,
    };
    serde_json::from_slice(&evaluate_package_intent_extract(&request).unwrap()).unwrap()
}

/// What one `package_intent_parse` of `command` answers, the way Python used
/// to ask for each candidate.
fn parsed(command: &str) -> (Option<Value>, Option<Value>) {
    let request = PackageIntentParseRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        command_text: command.to_owned(),
        workspace: None,
        home_dir: None,
        canonical_command: None,
        environment: None,
    };
    let result: PackageIntentParseResultV1 =
        serde_json::from_slice(&evaluate_package_intent_parse(&request).unwrap()).unwrap();
    (result.payload, result.runtime_private_metadata)
}

fn answer(result: &PackageIntentParseResultV1) -> (Option<Value>, Option<Value>) {
    (
        result.payload.clone(),
        result.runtime_private_metadata.clone(),
    )
}

#[test]
fn a_shell_call_answers_its_first_command_that_names_a_package() {
    let result = extract(
        json!(" Bash "),
        json!({"command": "ls -la", "commands": ["git status", "npm install left-pad"]}),
        Some("pip install requests"),
    );
    assert_eq!((result.status.as_str(), result.code.as_str()), ("ok", "ok"));
    assert_eq!(answer(&result), parsed("npm install left-pad"));
    assert!(result.payload.as_ref().is_some_and(Value::is_object));
    assert!(result.runtime_private_metadata.is_some());

    // An argv list is one command.
    let argv = extract(
        json!("shell"),
        json!({"argv": ["npm", "install", "left-pad"]}),
        None,
    );
    assert_eq!(answer(&argv), parsed("npm install left-pad"));
}

#[test]
fn the_action_envelope_command_answers_when_no_argument_names_a_package() {
    let quiet_shell = extract(
        json!("bash"),
        json!({"command": "ls"}),
        Some("pip install requests"),
    );
    assert_eq!(answer(&quiet_shell), parsed("pip install requests"));

    // A tool that is not a shell never has its arguments read as commands.
    let editor = extract(
        json!("write_file"),
        json!({"command": "npm install left-pad"}),
        Some("pip install requests"),
    );
    assert_eq!(answer(&editor), parsed("pip install requests"));
    let unnamed = extract(json!(7), json!({"command": "npm install left-pad"}), None);
    assert_eq!(answer(&unnamed), (None, None));
}

#[test]
fn a_call_that_names_no_package_answers_no_intent() {
    for (tool_name, arguments, envelope) in [
        (json!("bash"), json!({"command": "ls"}), None),
        (json!("bash"), json!({"command": "ls"}), Some("")),
        (json!("bash"), Value::Null, Some("git status")),
        (json!("write_file"), json!({"command": "npm i x"}), None),
    ] {
        let result = extract(tool_name, arguments, envelope);
        assert_eq!((result.status.as_str(), result.code.as_str()), ("ok", "ok"));
        assert_eq!(answer(&result), (None, None));
    }
}

#[test]
fn the_reply_binds_to_its_request_and_refuses_a_foreign_schema() {
    let mut request = PackageIntentExtractRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "req-9".to_owned(),
        tool_name: json!("bash"),
        arguments: json!({"command": "npm install left-pad"}),
        action_envelope_command: None,
        workspace: None,
        home_dir: None,
        environment: None,
    };
    let reply: PackageIntentParseResultV1 =
        serde_json::from_slice(&evaluate_package_intent_extract(&request).unwrap()).unwrap();
    assert_eq!(reply.request_id, "req-9");
    assert_eq!(
        reply.request_sha256,
        request_digest_with_limit(&request, PACKAGE_INTENT_EXTRACT_MAX_BYTES).unwrap()
    );

    request.schema = "guard-package-authority-request.v0".to_owned();
    let refused: Value =
        serde_json::from_slice(&evaluate_package_intent_extract(&request).unwrap()).unwrap();
    assert_eq!(refused["status"], json!("error"));
    assert_eq!(refused["code"], json!("schema_mismatch"));

    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&guard_contracts::PACKAGE_INTENT_EXTRACT_FEATURE));

    // A request past its bound is refused before anything is parsed.
    request.schema = PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned();
    request.arguments = json!({"command": "x".repeat(PACKAGE_INTENT_EXTRACT_MAX_BYTES)});
    assert!(evaluate_package_intent_extract(&request).is_err());
}
