use super::*;
use serde_json::Value;
use std::io::{self, Cursor};

fn build_request() -> Value {
    let source = json!({
        "apiVersion":"guard.hashgraphonline.com/v1alpha1", "kind":"GuardPolicy",
        "metadata":{"id":"policy.source", "name":"private-source-marker", "revision":1},
        "spec":{"defaults":{"mode":"enforce", "defaultAction":"block"},
            "rules":[{"id":"mail.rule", "enabled":true, "effect":"review",
                "match":{"business":{"schema":"guard.business-policy-match.v1", "version":1,
                    "services":["google_gmail"], "operations":["mail_send"]}},
                "lifetime":{"mode":"permanent"},
                "provenance":{"source":"local", "createdAt":"2026-07-15T00:00:00Z"}}]}
    });
    json!({"schema":"guard.business-source-build.v1", "version":1,
        "verifier_key":vec![9u8;32], "mutation_revision":1, "import_mode":"replace",
        "source_json":String::from_utf8(canonical_json_bytes(&source).unwrap()).unwrap()})
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn verify_request(record: &[u8]) -> Value {
    json!({"schema":"guard.business-source-verify.v1", "version":1,
        "verifier_key":vec![9u8;32], "record_json":String::from_utf8(record.to_vec()).unwrap()})
}

#[test]
fn native_codec_authenticates_full_source_without_install_or_approval_claims() {
    let request = build_request();
    let record = run_command("business-source-build", Cursor::new(bytes(&request))).unwrap();
    let response = run_command(
        "business-source-verify",
        Cursor::new(bytes(&verify_request(&record))),
    )
    .unwrap();
    let response: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(response["authentication"], "provided_key_verified");
    assert_eq!(response["approval"], "not_checked");
    assert_eq!(response["currentness"], "not_checked");
    assert_eq!(response["installed"], false);
    assert_eq!(
        response["source_digest"],
        response["business_policy"]["sourceDocumentDigest"]
    );
    assert_eq!(response["retained_identity"]["mutation_revision"], 1);
}

#[test]
fn source_and_record_duplicates_and_claimed_authority_refuse() {
    let original = build_request();
    for case in ["duplicate-source", "merge", "extra-authority", "null-key"] {
        let mut request = original.clone();
        match case {
            "duplicate-source" => {
                let text = request["source_json"].as_str().unwrap().replacen(
                    "\"revision\":1",
                    "\"revision\":1,\"revision\":1",
                    1,
                );
                assert_eq!(text.matches("\"revision\":1").count(), 2);
                request["source_json"] = json!(text);
            }
            "merge" => request["import_mode"] = json!("merge"),
            "extra-authority" => request["approved"] = json!(true),
            _ => request["verifier_key"] = Value::Null,
        }
        assert_eq!(
            run_command("business-source-build", Cursor::new(bytes(&request))),
            Err(ERROR.into())
        );
    }
    let record = run_command("business-source-build", Cursor::new(bytes(&original))).unwrap();
    let mut request = verify_request(&record);
    request["record_json"] = json!(String::from_utf8(record).unwrap().replacen(
        "\"revision\":1",
        "\"revision\":1,\"revision\":1",
        1,
    ));
    assert_eq!(
        run_command("business-source-verify", Cursor::new(bytes(&request))),
        Err(ERROR.into())
    );
}

#[test]
fn forged_record_and_wrong_key_only_expose_finite_diagnostic() {
    let record = run_command(
        "business-source-build",
        Cursor::new(bytes(&build_request())),
    )
    .unwrap();
    let mut request = verify_request(&record);
    request["verifier_key"] = json!(vec![8u8; 32]);
    assert_eq!(
        run_command("business-source-verify", Cursor::new(bytes(&request))),
        Err(ERROR.into())
    );
    let mut value: Value = serde_json::from_slice(&record).unwrap();
    value["source_document"]["metadata"]["name"] = json!("private-tamper-marker");
    let request = verify_request(&canonical_json_bytes(&value).unwrap());
    assert_eq!(
        run_command("business-source-verify", Cursor::new(bytes(&request))),
        Err(ERROR.into())
    );
}

struct InterruptedOnce {
    interrupted: bool,
    bytes: Cursor<Vec<u8>>,
}

impl Read for InterruptedOnce {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.bytes.read(output)
    }
}

#[test]
fn reader_handles_interruption_and_refuses_oversize_or_trailing_data() {
    let request = bytes(&build_request());
    let reader = InterruptedOnce {
        interrupted: false,
        bytes: Cursor::new(request.clone()),
    };
    run_command("business-source-build", reader).unwrap();
    let mut trailing = request;
    trailing.extend_from_slice(b" null");
    assert_eq!(
        run_command("business-source-build", Cursor::new(trailing)),
        Err(ERROR.into())
    );
    assert_eq!(
        run_command(
            "business-source-build",
            Cursor::new(vec![0; MAX_REQUEST_BYTES + 1])
        ),
        Err(ERROR.into())
    );
}

#[test]
fn marker_codec_binds_phase_without_claiming_retention_or_approval() {
    let source = run_command(
        "business-source-build",
        Cursor::new(bytes(&build_request())),
    )
    .unwrap();
    for phase in ["closed", "committed"] {
        let request = json!({"schema":"guard.business-source-anchor-build.v1", "version":1,
            "verifier_key":vec![9u8;32], "record_json":String::from_utf8(source.clone()).unwrap(),
            "phase":phase});
        let marker =
            run_command("business-source-anchor-build", Cursor::new(bytes(&request))).unwrap();
        let request = json!({"schema":"guard.business-source-anchor-verify.v1", "version":1,
            "verifier_key":vec![9u8;32], "anchor_json":String::from_utf8(marker).unwrap()});
        let result = run_command(
            "business-source-anchor-verify",
            Cursor::new(bytes(&request)),
        )
        .unwrap();
        let result: Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(result["phase"], phase);
        assert_eq!(result["retention"], "not_checked");
        assert_eq!(result["approval"], "not_checked");
        assert_eq!(result["installed"], false);
    }
}
