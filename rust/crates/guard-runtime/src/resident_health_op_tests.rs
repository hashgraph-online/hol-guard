use super::*;

use serde_json::Value;

fn request(request_id: &str) -> ResidentHealthRequestV1 {
    ResidentHealthRequestV1 {
        schema: RESIDENT_HEALTH_REQUEST_SCHEMA.to_owned(),
        request_id: request_id.to_owned(),
    }
}

fn decode(request: &ResidentHealthRequestV1) -> ResidentHealthResultV1 {
    serde_json::from_slice(&evaluate_resident_health(request).unwrap()).unwrap()
}

#[test]
fn answers_serving_with_the_lane_shape_the_transport_uses() {
    let result = decode(&request("req-1"));

    assert_eq!(result.schema, RESIDENT_HEALTH_RESULT_SCHEMA);
    assert_eq!(result.request_id, "req-1");
    assert!(result.request_sha256.starts_with("sha256:"));
    assert_eq!(result.status, "serving");
    assert_eq!(result.protocol_version, crate::RESIDENT_PROTOCOL_VERSION);
    assert_eq!(result.runtime_version, crate::PACKAGE_VERSION);
    assert_eq!(result.build_sha, crate::BUILD_SHA);
    assert_eq!(
        result.target,
        format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
    );

    let (evaluation, control) = crate::resident_transport::lane_shape();
    assert_eq!(
        (result.evaluation.workers, result.evaluation.queue_capacity),
        (
            u32::try_from(evaluation.0).unwrap(),
            u32::try_from(evaluation.1).unwrap()
        )
    );
    assert_eq!(
        (result.control.workers, result.control.queue_capacity),
        (
            u32::try_from(control.0).unwrap(),
            u32::try_from(control.1).unwrap()
        )
    );
    assert!(result.control.workers >= 1 && result.control.queue_capacity >= 1);
    // A depth is only readable against the capacity beside it, so both lanes
    // report theirs, and neither claims to have held more than it ever did.
    assert!(result.evaluation.queued <= result.evaluation.queued_max);
    assert!(result.control.queued <= result.control.queued_max);
}

#[test]
fn separates_a_loaded_resident_from_a_dead_one() {
    let before = decode(&request("req-before")).overloaded_requests;
    record_overload();
    let after = decode(&request("req-after"));

    // A refusal moves the counter while the status stays `serving`: the caller
    // reads load, not death. A dead resident sends no reply at all. The counter
    // is process-wide, so another test's refusal may lift it further.
    assert!(after.overloaded_requests > before);
    assert_eq!(after.status, "serving");
}

#[test]
fn carries_the_aggregate_counters_a_loaded_resident_is_read_by() {
    // `serving` alone cannot tell a resident that is answering quickly from
    // one that is answering every request late, or one that is refusing frames
    // it cannot read. These counters are that difference.
    let before = decode(&request("req-counters-before")).counters;
    crate::resident_health_counters::record_frame_error();
    let after = decode(&request("req-counters-after")).counters;

    assert!(after.frame_errors > before.frame_errors);
    // Counters only rise, so the reply a caller reads never shows the resident
    // having done less work than the one before it did.
    assert!(after.served_requests >= before.served_requests);
}

#[test]
fn uptime_starts_at_zero_until_the_worker_pools_say_otherwise() {
    // The clock is set once by `start_resident_workers`; no reply observed by a
    // served request can read zero, and a handoff cannot rewind it.
    let first = uptime_ms();
    mark_serving();
    let second = uptime_ms();
    mark_serving();
    assert!(second >= first);
    assert!(uptime_ms() >= second);
}

#[test]
fn refuses_a_foreign_schema_and_a_missing_request_id() {
    let mut foreign = request("req-1");
    foreign.schema = "guard-resident-health-request.v2".to_owned();
    assert_eq!(
        evaluate_resident_health(&foreign).unwrap_err(),
        "native_resident_health_schema_mismatch"
    );

    assert_eq!(
        evaluate_resident_health(&request("")).unwrap_err(),
        "native_resident_health_invalid"
    );
}

#[test]
fn refuses_a_request_past_the_byte_budget() {
    let oversized = ResidentHealthRequestV1 {
        schema: RESIDENT_HEALTH_REQUEST_SCHEMA.to_owned(),
        request_id: "r".repeat(RESIDENT_HEALTH_MAX_REQUEST_BYTES + 1),
    };

    assert!(evaluate_resident_health(&oversized).is_err());
}

#[test]
fn says_nothing_about_the_work_the_resident_is_doing() {
    // A diagnostic that may read this reply is not allowed to read requests,
    // paths or commands, so the reply must carry none of them. Every field is a
    // count, a duration or a build identifier.
    let request = ResidentHealthRequestV1 {
        schema: RESIDENT_HEALTH_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
    };
    let encoded = evaluate_resident_health(&request).unwrap();
    let value: Value = serde_json::from_slice(&encoded).unwrap();

    // `serde_json` is built without `preserve_order`, so an object's keys read
    // back sorted whatever order the struct declares them in.
    let mut fields: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        vec![
            "build_sha",
            "control",
            "counters",
            "evaluation",
            "overloaded_requests",
            "protocol_version",
            "request_id",
            "request_sha256",
            "runtime_version",
            "schema",
            "status",
            "target",
            "uptime_ms",
        ]
    );
    for lane in ["evaluation", "control"] {
        let mut keys: Vec<&str> = value[lane]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["queue_capacity", "queued", "queued_max", "workers"]
        );
    }
}

#[test]
fn advertises_the_operation_so_a_caller_can_tell_an_older_resident_apart() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&guard_contracts::RESIDENT_HEALTH_FEATURE));
}
