use super::*;
use guard_contracts::PosixTerminalSignalsV1;

fn signals() -> PosixTerminalSignalsV1 {
    PosixTerminalSignalsV1 {
        controlling_terminal_opened: true,
        controlling_terminal_is_tty: true,
        stdin_is_tty: true,
        descriptors_share_session: Some(true),
        terminal_name: "/dev/ttys020".to_string(),
        login_name: Some("operator".to_string()),
        who_output: Some("operator ttys020  Oct 27 09:14\n".to_string()),
        logind_remote: None,
        terminal_owner_uid: Some(501),
        terminal_is_char_device: Some(true),
        effective_uid: 501,
    }
}

fn request() -> ExtensionControlTerminalRequestV1 {
    ExtensionControlTerminalRequestV1 {
        schema: EXTENSION_CONTROL_TERMINAL_REQUEST_SCHEMA.to_owned(),
        request_id: "request-1".to_owned(),
        remote_environment: Vec::new(),
        posix: Some(signals()),
        windows: None,
    }
}

fn decode(request: &ExtensionControlTerminalRequestV1) -> Value {
    let bytes = evaluate_extension_control_terminal_request(request).expect("encoded response");
    serde_json::from_slice(&bytes).expect("json response")
}

#[test]
fn a_local_session_answers_ok_and_binds_to_its_request() {
    let request = request();
    let response = decode(&request);
    assert_eq!(response["schema"], EXTENSION_CONTROL_TERMINAL_RESULT_SCHEMA);
    assert_eq!(response["request_id"], "request-1");
    assert_eq!(response["status"], "ok");
    assert_eq!(response["code"], "ok");
    assert_eq!(response["payload"]["verdict"], "local");
    let digest = response["request_sha256"].as_str().expect("digest");
    assert_eq!(
        digest,
        request_digest_with_limit(&request, EXTENSION_CONTROL_TERMINAL_MAX_BYTES).expect("digest")
    );
}

#[test]
fn a_remote_session_answers_ok_with_a_refusing_verdict() {
    let mut request = request();
    request.remote_environment = vec!["SSH_TTY".to_owned()];
    let response = decode(&request);
    assert_eq!(response["status"], "ok");
    assert_eq!(response["payload"]["verdict"], "remote_terminal");
}

#[test]
fn a_wrong_schema_is_refused() {
    let mut request = request();
    request.schema = "guard-extension-control-terminal-request.v2".to_owned();
    let response = decode(&request);
    assert_eq!(response["status"], "error");
    assert_eq!(response["code"], INVALID);
    assert!(response.get("payload").is_none());
}

#[test]
fn an_empty_request_id_is_refused() {
    let mut request = request();
    request.request_id = String::new();
    let response = decode(&request);
    assert_eq!(response["status"], "error");
    assert_eq!(response["code"], INVALID);
}

#[test]
fn a_request_without_a_platform_block_is_refused() {
    let mut request = request();
    request.posix = None;
    let response = decode(&request);
    assert_eq!(response["status"], "error");
    assert_eq!(response["code"], INVALID);
}
