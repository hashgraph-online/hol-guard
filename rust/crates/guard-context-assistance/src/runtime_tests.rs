use super::*;
use guard_cigar_native::{CORE_VERSION, WORKER_PROTOCOL};

fn doctor() -> Value {
    json!({"capabilities": {
        "schema": "cigar.local-worker-capabilities.v1", "core_version": CORE_VERSION,
        "protocol": WORKER_PROTOCOL, "execution": "isolated-process-serialized",
        "authority": "trusted-host", "requires_hol_services": false,
        "max_frame_bytes": 33554432, "max_response_bytes": 67108864,
        "features": ["context_graph.v1", "context_views.v1", "snapshot_integrity.v1", "source_replace.v1", "selection_explanation.v1"]
    }, "compile_verified": true, "rendered_tokens": 24})
}

#[test]
fn doctor_requires_exact_protocol_features_and_actual_compile() {
    assert_eq!(verify_doctor(&doctor()).unwrap().len(), 5);
    for (key, value) in [
        ("core_version", json!("0.14.0")),
        ("protocol", json!("cigar.context-worker.v2")),
        ("features", json!(["context_graph.v1"])),
        ("max_frame_bytes", json!(1)),
        ("requires_hol_services", json!(true)),
    ] {
        let mut report = doctor();
        report["capabilities"][key] = value;
        assert_eq!(verify_doctor(&report), Err(RuntimeError::HandshakeFailed));
    }
    for (key, value) in [
        ("compile_verified", json!(false)),
        ("rendered_tokens", json!(257)),
        ("rendered_tokens", json!(0)),
    ] {
        let mut report = doctor();
        report[key] = value;
        assert_eq!(verify_doctor(&report), Err(RuntimeError::HandshakeFailed));
    }
}
