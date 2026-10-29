//! Only the paths that refuse or pass through without a decoder are unit
//! tested here: anything reaching `contained_decode` would sandbox the test
//! process itself. The contained decode is exercised end to end by spawning
//! the runtime binary from the Python suite.

use super::*;
use guard_contracts::ContentDecodeCapsV1;

fn request(content_encoding: &[&str], body: &[u8]) -> ContentDecodeRequestV1 {
    ContentDecodeRequestV1 {
        schema: CONTENT_DECODE_REQUEST_SCHEMA.to_owned(),
        request_id: "0123456789abcdef0123456789abcdef".to_owned(),
        content_encoding: content_encoding.iter().map(|v| (*v).to_owned()).collect(),
        body_base64: STANDARD.encode(body),
        state_dir: "/nonexistent-guard-state".to_owned(),
        timeout_ms: 5_000,
        caps: ContentDecodeCapsV1 {
            max_input_bytes: 1024,
            max_output_bytes: 64 * 1024,
            max_ratio: 100,
            max_layers: 2,
            max_memory_bytes: 256 * 1024 * 1024,
        },
    }
}

fn run(
    request: &ContentDecodeRequestV1,
) -> (Result<Vec<u8>, ContentDecodeError>, ContentDecodeCounters) {
    let mut counters = ContentDecodeCounters::default();
    let result = decode_request(request, 0, Instant::now(), &mut counters);
    (result, counters)
}

fn refused(request: &ContentDecodeRequestV1) -> (ContentDecodeStatus, &'static str) {
    let (result, counters) = run(request);
    assert_eq!(counters.decoder_calls, 0);
    let error = result.unwrap_err();
    (error.status, error.code)
}

#[test]
fn identity_bodies_pass_through_without_a_decoder() {
    for values in [&[][..], &["identity"][..], &["Identity, identity"][..]] {
        let (result, counters) = run(&request(values, b"plain body"));
        assert_eq!(result.unwrap(), b"plain body");
        assert_eq!(counters.decoder_calls, 0);
        assert_eq!(counters.input_bytes, 10);
        assert_eq!(counters.output_bytes, 10);
    }
}

#[test]
fn unsupported_and_over_deep_codings_are_refused_before_decode() {
    for values in [&["zstd"][..], &["gzip;q=1"][..], &["br", "compress"][..]] {
        assert_eq!(
            refused(&request(values, b"x")),
            (ContentDecodeStatus::Rejected, "content_coding_unsupported")
        );
    }
    assert_eq!(
        refused(&request(&["gzip, gzip, br"], b"x")),
        (ContentDecodeStatus::Rejected, "content_coding_too_deep")
    );
}

#[test]
fn oversized_bodies_are_refused_before_decode() {
    let big = vec![0u8; 1025];
    assert_eq!(
        refused(&request(&["br"], &big)),
        (ContentDecodeStatus::Rejected, "content_input_too_large")
    );
    // The encoded form is bounded before it is decoded at all.
    let mut oversized = request(&["br"], b"x");
    oversized.body_base64 = "A".repeat(4096);
    assert_eq!(
        refused(&oversized),
        (ContentDecodeStatus::Rejected, "content_input_too_large")
    );
}

#[test]
fn malformed_base64_is_an_invalid_request() {
    let mut bad = request(&["br"], b"x");
    bad.body_base64 = "not base64!".to_owned();
    assert_eq!(
        refused(&bad),
        (
            ContentDecodeStatus::Incomplete,
            "content_decode_request_invalid"
        )
    );
}

#[test]
fn policies_outside_the_runtime_bounds_are_refused() {
    let edits: [fn(&mut ContentDecodeRequestV1); 10] = [
        |r| r.schema = "guard-content-decode.v0".to_owned(),
        |r| r.request_id = "ABCDEF".to_owned(),
        |r| r.content_encoding = vec!["gzip".to_owned(); CONTENT_CAP_HEADER_VALUES + 1],
        |r| r.state_dir = String::new(),
        |r| r.timeout_ms = 0,
        |r| r.timeout_ms = CONTENT_CAP_TIMEOUT_MS + 1,
        |r| r.caps.max_input_bytes = CONTENT_CAP_INPUT_BYTES + 1,
        |r| r.caps.max_output_bytes = 0,
        |r| r.caps.max_layers = CONTENT_CAP_LAYERS + 1,
        |r| r.caps.max_memory_bytes = CONTENT_CAP_MEMORY_BYTES + 1,
    ];
    for edit in edits {
        let mut policy = request(&["br"], b"x");
        edit(&mut policy);
        assert_eq!(
            refused(&policy),
            (
                ContentDecodeStatus::Incomplete,
                "content_decode_policy_invalid"
            )
        );
    }
}

#[test]
fn requests_with_unknown_fields_are_refused() {
    let mut value = serde_json::to_value(request(&[], b"x")).unwrap();
    value["destination"] = serde_json::json!("https://example.test/");
    assert!(serde_json::from_value::<ContentDecodeRequestV1>(value).is_err());
}
