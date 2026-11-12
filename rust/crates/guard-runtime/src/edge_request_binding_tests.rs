use super::*;

/// The golden vectors a review reads in Python. Rust pins the half a review
/// cannot check for itself: that every vector is a well-formed edge answer, so
/// the id is the only thing telling this request's verdict from another's.
const BINDING_VECTORS: &str =
    include_str!("../../../../tests/fixtures/edge-request-binding.v1.json");

fn vectors() -> Value {
    serde_json::from_str(BINDING_VECTORS).expect("binding vectors parse")
}

#[test]
fn every_binding_vector_is_a_well_formed_edge_answer() {
    let fixture = vectors();
    assert_eq!(fixture["schema"], "guard-edge-request-binding.v1");
    let cases = fixture["vectors"].as_array().expect("vectors array");
    assert!(cases.len() >= 6, "vectors: {}", cases.len());
    for case in cases {
        let name = case["name"].as_str().expect("vector name");
        let edge: GuardHookEdgeResultV2 = serde_json::from_value(case["edge"].clone())
            .unwrap_or_else(|error| {
                panic!("vector {name} is not an edge result: {error}");
            });
        assert_eq!(edge.schema, GUARD_HOOK_EDGE_RESULT_V2_SCHEMA, "{name}");
        assert_eq!(edge.authority, "rust", "{name}");
        serde_json::from_value::<PreToolResultV1>(edge.result.clone())
            .unwrap_or_else(|error| panic!("vector {name} carries no pre-tool result: {error}"));
        assert!(!edge.receipt.decision_id.is_empty(), "{name}");
    }
}

#[test]
fn a_vector_is_bound_only_when_both_ids_name_this_request() {
    let fixture = vectors();
    let mine = fixture["request_id"].as_str().expect("request id");
    let theirs = fixture["foreign_request_id"]
        .as_str()
        .expect("foreign request id");
    assert_ne!(mine, theirs);
    assert!(request_id_is_safe(mine), "{mine}");
    assert!(request_id_is_safe(theirs), "{theirs}");
    let mut bound = 0usize;
    let mut unbound = 0usize;
    for case in fixture["vectors"].as_array().expect("vectors array") {
        let name = case["name"].as_str().expect("vector name");
        let edge: GuardHookEdgeResultV2 =
            serde_json::from_value(case["edge"].clone()).expect("edge result");
        let binds = edge.request_id.as_deref() == Some(mine) && edge.receipt.request_id == mine;
        assert_eq!(
            binds,
            case["bound"].as_bool().expect("bound flag"),
            "vector {name} disagrees with its binding"
        );
        if binds {
            bound += 1;
        } else {
            unbound += 1;
        }
    }
    assert!(bound >= 2, "bound vectors: {bound}");
    assert!(unbound >= 4, "unbound vectors: {unbound}");
}

#[test]
fn the_resident_tells_a_caller_that_the_edge_echoes_its_request_id() {
    let features = crate::resident_protocol::capabilities().features;
    assert!(
        features
            .iter()
            .any(|feature| feature == REQUEST_BINDING_FEATURE),
        "{REQUEST_BINDING_FEATURE} is not published"
    );
}
