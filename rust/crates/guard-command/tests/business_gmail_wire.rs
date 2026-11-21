use base64::{engine::general_purpose, Engine};
use guard_command::business_gmail_wire::*;
use guard_contracts::MAX_BUSINESS_INLINE_BYTES;
use serde_json::json;
use sha2::{Digest, Sha256};

const MIME: &[u8] = b"From: sender@example.test\r\nTo: recipient@example.test\r\nBcc: hidden@example.test\r\nSubject: Fixture\r\n\r\nPrivate fixture body";

fn body(raw: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"raw": raw, "threadId": "thread-fixture"})).unwrap()
}

fn params() -> Vec<u8> {
    br#"{"userId":"me"}"#.to_vec()
}

#[test]
fn committed_provider_export_matches_the_pin_and_decoder_profile() {
    let bytes = include_bytes!(
        "../../../../contracts/business-policy/providers/gws-v0.22.5-gmail-send.schema.json"
    );
    assert_eq!(
        hex::encode(Sha256::digest(bytes)),
        GWS_GMAIL_SEND_SCHEMA_DIGEST
    );
    let export: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    assert_eq!(export["httpMethod"], "POST");
    assert_eq!(export["path"], "gmail/v1/users/{userId}/messages/send");
    assert_eq!(export["parameters"].as_object().unwrap().len(), 1);
    assert_eq!(export["parameters"]["userId"]["type"], "string");
    assert_eq!(export["parameters"]["userId"]["default"], "me");
    assert_eq!(export["parameters"]["userId"]["required"], true);
    let properties = export["requestBody"]["schema"]["properties"]
        .as_object()
        .unwrap();
    assert_eq!(properties["raw"]["type"], "string");
    assert_eq!(properties["raw"]["format"], "byte");
    assert_eq!(properties["threadId"]["type"], "string");
    for field in properties
        .keys()
        .filter(|field| *field != "raw" && *field != "threadId")
    {
        let mut value = json!({"raw":"Zg"});
        value[field] = json!(null);
        assert!(
            matches!(
                decode_body(serde_json::to_vec(&value).unwrap()),
                Err(GmailSendWireErrorV1::Invalid)
            ),
            "{field}"
        );
    }
}

fn decode_body(bytes: Vec<u8>) -> Result<GmailSendWireInputV1, GmailSendWireErrorV1> {
    GmailSendWireInputV1::from_owned_json(params(), bytes)
}

#[test]
fn owns_exact_wire_and_decoded_private_bytes() {
    let parameter_bytes = params();
    let request = body(&general_purpose::URL_SAFE_NO_PAD.encode(MIME));
    let input =
        GmailSendWireInputV1::from_owned_json(parameter_bytes.clone(), request.clone()).unwrap();
    assert_eq!(input.params_bytes(), parameter_bytes);
    assert_eq!(input.body_bytes(), request);
    assert_eq!(input.mime_bytes(), MIME);
    assert_eq!(input.thread_id(), Some("thread-fixture"));
    assert_eq!(input.input_binding().len(), 64);
    // Ownership exposes immutable bytes, with no path/stdin/target execution.
}

#[test]
fn padded_unpadded_and_binary_content_decode_without_mutation() {
    // Fixed vectors independently produced with Python's urlsafe_b64encode.
    for (raw, expected) in [
        ("Zg", b"f".as_slice()),
        ("Zg==", b"f"),
        ("APv_DQo", &[0, 251, 255, 13, 10]),
    ] {
        assert_eq!(decode_body(body(raw)).unwrap().mime_bytes(), expected);
    }
    for bytes in [MIME, &[0, 251, 255, 13, 10][..]] {
        for engine in [
            &general_purpose::URL_SAFE,
            &general_purpose::URL_SAFE_NO_PAD,
        ] {
            let input = decode_body(body(&engine.encode(bytes))).unwrap();
            assert_eq!(input.mime_bytes(), bytes);
        }
    }
    // Binary decoding does not assert RFC validity or complete business facts.
}

#[test]
fn malformed_encoding_is_rejected_without_diagnostics_containing_input() {
    for raw in [
        "", "A", "Zg=", "Zg===", "Zh", "Zh==", "+/8=", "Z g==", "Zg==\n", "Zg==Zg", "Z☃",
    ] {
        assert!(
            matches!(decode_body(body(raw)), Err(GmailSendWireErrorV1::Invalid)),
            "{raw}"
        );
    }
    assert_eq!(format!("{:?}", GmailSendWireErrorV1::Invalid), "Invalid");
}

#[test]
fn unknown_duplicate_missing_and_null_fields_are_not_dropped() {
    for bytes in [
        br#"{"raw":"Zg","raw":"Zw"}"#.as_slice(),
        br#"{"r\u0061w":"Zg","raw":"Zw"}"#,
        br#"{"raw":"Zg","threadId":"a","threadId":"b"}"#,
        br#"{"raw":"Zg","threadId":null}"#,
        br#"{"raw":"Zg","threadId":1}"#,
        br#"{"raw":"Zg","payload":{}}"#,
        br#"{"raw":"Zg","labelIds":["INBOX"]}"#,
        br#"{"raw":"Zg","classificationLabelValues":[]}"#,
        br#"{"raw":null}"#,
        br#"{}"#,
    ] {
        assert!(matches!(
            decode_body(bytes.to_vec()),
            Err(GmailSendWireErrorV1::Invalid)
        ));
    }
    for bytes in [
        br#"{}"#.as_slice(),
        br#"{"userId":null}"#,
        br#"{"userId":"me","userId":"other"}"#,
        br#"{"userId":"me","uploadType":"media"}"#,
    ] {
        assert!(matches!(
            GmailSendWireInputV1::from_owned_json(bytes.to_vec(), body("Zg")),
            Err(GmailSendWireErrorV1::Invalid)
        ));
    }
}

#[test]
fn a_principal_selector_never_substitutes_for_authenticated_identity() {
    for user in ["", "ME", "sender@example.test", "../me", "me "] {
        assert!(matches!(
            GmailSendWireInputV1::from_owned_json(
                serde_json::to_vec(&json!({"userId":user})).unwrap(),
                body("Zg")
            ),
            Err(GmailSendWireErrorV1::UnsupportedPrincipalSelector)
        ));
    }
    assert!(decode_body(br#"{"raw":"Zg"}"#.to_vec())
        .unwrap()
        .thread_id()
        .is_none());
}

#[test]
fn input_bounds_apply_before_json_or_decoding_and_resource_ids_are_bounded() {
    let mut full_params = params();
    full_params.resize(GMAIL_SEND_MAX_PARAM_BYTES, b' ');
    assert!(GmailSendWireInputV1::from_owned_json(full_params, body("Zg")).is_ok());
    let mut full_body = body("Zg");
    full_body.resize(MAX_BUSINESS_INLINE_BYTES as usize - params().len(), b' ');
    assert!(decode_body(full_body.clone()).is_ok());
    full_body.push(b' ');
    assert!(matches!(
        decode_body(full_body),
        Err(GmailSendWireErrorV1::BoundsExceeded)
    ));
    assert!(decode_body(
        serde_json::to_vec(&json!({"raw":"Zg","threadId":"a".repeat(256)})).unwrap()
    )
    .is_ok());
    assert!(matches!(
        GmailSendWireInputV1::from_owned_json(
            vec![b' '; GMAIL_SEND_MAX_PARAM_BYTES + 1],
            body("Zg")
        ),
        Err(GmailSendWireErrorV1::BoundsExceeded)
    ));
    assert!(matches!(
        decode_body(vec![b' '; MAX_BUSINESS_INLINE_BYTES as usize + 1]),
        Err(GmailSendWireErrorV1::BoundsExceeded)
    ));
    for id in [String::new(), "a".repeat(257), "line\nfeed".into()] {
        assert!(matches!(
            decode_body(serde_json::to_vec(&json!({"raw":"Zg","threadId":id})).unwrap()),
            Err(GmailSendWireErrorV1::Invalid)
        ));
    }
}

#[test]
fn body_thread_and_parameter_bytes_all_change_the_preparation_binding() {
    let baseline = decode_body(body("Zg")).unwrap();
    // SHA-256 of the domain/schema and u64 big-endian framed wire bytes,
    // computed independently with Python hashlib + struct.pack.
    assert_eq!(
        baseline.input_binding(),
        "b844c2ab672df1abcf2af755f72c061fc2d31413b0c1f50c89cae533a2c255d5"
    );
    for changed in [
        body("Zw"),
        br#"{"raw":"Zg","threadId":"another-thread"}"#.to_vec(),
        br#"{ "raw":"Zg","threadId":"thread-fixture" }"#.to_vec(),
    ] {
        assert_ne!(
            baseline.input_binding(),
            decode_body(changed).unwrap().input_binding()
        );
    }
    let input = GmailSendWireInputV1::from_owned_json(br#"{ "userId":"me" }"#.to_vec(), body("Zg"))
        .unwrap();
    assert_ne!(baseline.input_binding(), input.input_binding());
}
