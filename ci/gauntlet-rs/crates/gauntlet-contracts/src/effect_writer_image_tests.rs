use super::*;
use serde_json::json;

fn fixture() -> (Value, Vec<Value>) {
    let events = vec![json!({"sequence":1,"device":1,"inode":2,"owner":10004,
        "file_handle":{"kind":1,"bytes":"aabb"},"reported_pid":42,"pidfd_available":true,
        "writer":{"pid":42,"start_ticks":1234,"cgroup":"/product.service"}})];
    let image = json!({"event_sequence":1,"surface":"contained-output","writer_pid":42,
        "writer_start_ticks":1234,"unavailable_reason":null,
        "sample":{"executable_sha256":"a".repeat(64),"argv_sha256":"b".repeat(64),
            "observed_action":"serve-managed","uid":10004,"gid":10004,
            "namespace_pid":7,"parent_pid":41,"no_new_privileges":true,"seccomp_mode":2,
            "namespaces":{"mnt":{"device":4,"inode":5},"pid":{"device":4,"inode":6},
                "user":{"device":4,"inode":7}}}});
    (json!([image]), events)
}

#[test]
fn writer_images_require_bounded_unique_event_and_process_relations() {
    let (images, events) = fixture();
    assert!(validate_effect_writer_images(&images, &events));
    assert!(validate_effect_writer_images(&json!([]), &events));
    for (path, value) in [
        ("/0/event_sequence", json!(0)),
        ("/0/event_sequence", json!(2)),
        ("/0/event_sequence", json!(true)),
        ("/0/writer_pid", json!(43)),
        ("/0/writer_start_ticks", json!(1235)),
        ("/0/surface", json!("arbitrary")),
        ("/0/sample/uid", json!(0)),
        ("/0/sample/gid", json!(10001)),
        ("/0/sample/executable_sha256", json!("A".repeat(64))),
        ("/0/sample/argv_sha256", json!("a".repeat(63))),
        ("/0/sample/observed_action", json!("unbounded-command")),
        ("/0/sample/namespaces/mnt/inode", json!(true)),
        ("/0/sample/namespaces/pid/inode", json!(0)),
        ("/0/sample/parent_pid", json!(0)),
        ("/0/sample/namespace_pid", json!(0)),
        ("/0/sample/no_new_privileges", json!(false)),
        ("/0/sample/seccomp_mode", json!(1)),
        ("/0/unavailable_reason", json!("process-sample-unavailable")),
    ] {
        let mut bad = images.clone();
        *bad.pointer_mut(path).unwrap() = value;
        assert!(
            !validate_effect_writer_images(&bad, &events),
            "{path}: {bad}"
        );
    }
    let mut extra = images.clone();
    extra[0]["sample"]["raw_argv"] = json!("unwanted");
    assert!(!validate_effect_writer_images(&extra, &events));
    assert!(!validate_effect_writer_images(
        &json!([images[0], images[0]]),
        &events
    ));
    assert!(!validate_effect_writer_images(
        &json!(vec![images[0].clone(); MAX_EFFECT_WRITER_IMAGES + 1]),
        &events
    ));
    for path in ["/0/file_handle", "/0/writer", "/0/pidfd_available"] {
        let mut bad = json!(events);
        *bad.pointer_mut(path).unwrap() = Value::Null;
        assert!(!validate_effect_writer_images(
            &images,
            bad.as_array().unwrap()
        ));
    }
}

#[test]
fn unavailable_is_explicit_and_cannot_be_promoted_to_a_sample() {
    let (mut images, mut events) = fixture();
    images[0]["sample"] = Value::Null;
    assert!(!validate_effect_writer_images(&images, &events));
    images[0]["unavailable_reason"] = json!("process-sample-unavailable");
    assert!(validate_effect_writer_images(&images, &events));
    events[0]["writer"] = Value::Null;
    images[0]["writer_start_ticks"] = Value::Null;
    images[0]["unavailable_reason"] = json!("writer-unavailable");
    assert!(validate_effect_writer_images(&images, &events));
    images[0]["unavailable_reason"] = json!("arbitrary reason");
    assert!(!validate_effect_writer_images(&images, &events));
}
