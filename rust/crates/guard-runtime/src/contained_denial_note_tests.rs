use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use super::dispatch;
use crate::contained_workspace_sink_denial::{CONNECT_NOTE, EXEC_NOTE, GENERIC_NOTE};
use crate::runner_authority_op::ERR_INVALID;

fn answer(outputs: &[&[u8]]) -> Value {
    let encoded: Vec<String> = outputs
        .iter()
        .map(|output| STANDARD.encode(output))
        .collect();
    dispatch(&json!({"outputs": encoded})).expect("note answer")
}

#[test]
fn the_note_is_read_from_the_outputs_in_order() {
    let reply = answer(&[
        &b"PermissionError: [Errno 13] Permission denied"[..],
        &b"spawn EPERM"[..],
    ]);
    assert_eq!(reply["note"], EXEC_NOTE);
    assert_eq!(reply["loopback_denied"], false);
    let reply = answer(&[&b""[..], &b"Error: connect EPERM 127.0.0.1:8080"[..]]);
    assert_eq!(reply["note"], CONNECT_NOTE);
    assert_eq!(reply["loopback_denied"], true);
}

#[test]
fn output_that_is_not_utf8_is_still_read() {
    let reply =
        answer(&[&b"\xff\xfe binary\nOSError: [Errno 1] Operation not permitted: 'data'"[..]]);
    assert_eq!(reply["note"], GENERIC_NOTE);
}

#[test]
fn output_without_a_denial_gets_no_note() {
    let reply = answer(&[&b"all tests passed"[..]]);
    assert_eq!(reply["note"], Value::Null);
    assert_eq!(reply["loopback_denied"], false);
    assert_eq!(answer(&[])["note"], Value::Null);
}

#[test]
fn outputs_must_be_a_list_of_base64_strings() {
    for args in [
        json!({}),
        json!({"outputs": "b3V0"}),
        json!({"outputs": [7]}),
        json!({"outputs": ["not base64!"]}),
        json!([]),
    ] {
        assert_eq!(dispatch(&args), Err(ERR_INVALID));
    }
}
