use serde_json::{json, Value};

use super::dispatch;

fn ask(stage: &str, fields: Value) -> Result<Value, String> {
    let mut request = json!({"op": "publication_prepare_request", "stage": stage});
    for (key, value) in fields.as_object().unwrap() {
        request[key] = value.clone();
    }
    let answer = dispatch(&request).map_err(|error| error.to_string())?;
    match answer.get("error") {
        Some(error) => Err(error.to_string()),
        None => Ok(answer["value"].clone()),
    }
}

fn deadline(fields: Value) -> Result<Value, String> {
    let mut request =
        json!({"deadline": 130.0, "now": 100.0, "deadline_epoch": 1030.0, "wall": 1000.0});
    for (key, value) in fields.as_object().unwrap() {
        request[key] = value.clone();
    }
    ask("deadline", request)
}

#[test]
fn the_deadline_is_the_earlier_of_the_two_clocks() {
    assert_eq!(deadline(json!({})).unwrap()["deadline"], json!(130.0));
    assert_eq!(
        deadline(json!({"deadline_epoch": 1010.0})).unwrap()["deadline"],
        json!(110.0)
    );
    assert_eq!(
        deadline(json!({"deadline": 105.0})).unwrap()["deadline"],
        json!(105.0)
    );
}

#[test]
fn a_deadline_must_be_ahead_and_at_most_a_minute_away_on_both_clocks() {
    for fields in [
        json!({"deadline": 100.0}),
        json!({"deadline": 99.0}),
        json!({"deadline": 160.5}),
        json!({"deadline_epoch": 1000.0}),
        json!({"deadline_epoch": 1060.5}),
        json!({"deadline": null}),
        json!({"deadline": true}),
        json!({"deadline": "130"}),
        json!({"deadline_epoch": null}),
        json!({"wall": null}),
        json!({"now": null}),
    ] {
        let error = deadline(fields.clone()).unwrap_err();
        assert!(error.contains("deadline_invalid"), "{fields}: {error}");
    }
    assert!(deadline(json!({"deadline": 160.0, "deadline_epoch": 1060.0})).is_ok());
}

#[test]
fn an_operation_id_is_a_canonical_lowercase_uuid() {
    let good = "123e4567-e89b-42d3-a456-426614174000";
    assert!(ask("operation", json!({"operation_id": good})).is_ok());
    for bad in [
        json!("123E4567-E89B-42D3-A456-426614174000"),
        json!("123e4567e89b42d3a456426614174000"),
        json!("{123e4567-e89b-42d3-a456-426614174000}"),
        json!("urn:uuid:123e4567-e89b-42d3-a456-426614174000"),
        json!("123e4567-e89b-42d3-a456-42661417400"),
        json!("123e4567-e89b-42d3-a456-42661417400g"),
        json!(""),
        json!(7),
        Value::Null,
    ] {
        let error = ask("operation", json!({"operation_id": bad})).unwrap_err();
        assert!(error.contains("operation_id_invalid"), "{bad}: {error}");
    }
    assert!(ask("operation", json!({}))
        .unwrap_err()
        .contains("operation_id_invalid"));
}

fn native() -> Value {
    json!({"candidate": {"path": "/a"}, "predecessor": {"path": "/b"}})
}

#[test]
fn reviewed_digests_name_both_sides_in_sha256_hex() {
    let digest = "a".repeat(64);
    let ok = json!({"candidate": digest, "predecessor": digest});
    assert!(ask(
        "bindings",
        json!({"executable_digests": ok, "native": native()})
    )
    .is_ok());
    assert!(ask(
        "bindings",
        json!({"executable_digests": null, "native": native()})
    )
    .is_ok());
    assert!(ask("bindings", json!({"native": native()})).is_ok());
    for bad in [
        json!({"candidate": digest}),
        json!({"candidate": digest, "predecessor": digest, "extra": digest}),
        json!({"candidate": digest, "predecessor": "A".repeat(64)}),
        json!({"candidate": digest, "predecessor": "a".repeat(63)}),
        json!({"candidate": digest, "predecessor": 5}),
        json!({}),
        json!([]),
        json!("text"),
    ] {
        let error = ask(
            "bindings",
            json!({"executable_digests": bad, "native": native()}),
        )
        .unwrap_err();
        assert!(error.contains("artifact_digest_invalid"), "{bad}: {error}");
    }
}

#[test]
fn native_bindings_must_name_exactly_both_sides() {
    for bad in [
        json!({"candidate": {}}),
        json!({"candidate": {}, "predecessor": {}, "third": {}}),
        json!({}),
        json!([]),
        Value::Null,
    ] {
        let error = ask("bindings", json!({"native": bad})).unwrap_err();
        assert!(
            error.contains("native_runtime_bindings_missing"),
            "{bad}: {error}"
        );
    }
    assert!(ask("bindings", json!({}))
        .unwrap_err()
        .contains("native_runtime_bindings_missing"));
}

#[test]
fn a_bad_digest_is_reported_before_a_missing_binding() {
    let error = ask("bindings", json!({"executable_digests": {}, "native": {}})).unwrap_err();
    assert!(error.contains("artifact_digest_invalid"));
}

#[cfg(unix)]
#[test]
fn each_side_needs_an_absolute_artifact_and_runtime_path() {
    let artifacts = json!({"predecessor": {"path": "/p"}, "candidate": {"path": "/c"}});
    assert!(ask(
        "identity",
        json!({"artifacts": artifacts, "native": native()})
    )
    .is_ok());
    let cases = [
        (
            json!({"predecessor": {"path": "p"}, "candidate": {"path": "/c"}}),
            native(),
        ),
        (
            json!({"predecessor": {"path": "/p"}, "candidate": {}}),
            native(),
        ),
        (
            json!({"predecessor": {"path": 5}, "candidate": {"path": "/c"}}),
            native(),
        ),
        (
            artifacts.clone(),
            json!({"candidate": {"path": "/a"}, "predecessor": {"path": "b"}}),
        ),
        (
            artifacts.clone(),
            json!({"candidate": {"path": "/a"}, "predecessor": "/b"}),
        ),
        (
            artifacts.clone(),
            json!({"candidate": {"path": "/a"}, "predecessor": {}}),
        ),
    ];
    for (artifacts, native) in cases {
        let error = ask(
            "identity",
            json!({"artifacts": artifacts, "native": native}),
        )
        .unwrap_err();
        assert!(error.contains("artifact_identity_invalid"), "{error}");
    }
}

#[test]
fn an_unknown_stage_is_refused() {
    assert!(ask("other", json!({}))
        .unwrap_err()
        .contains("files_invalid"));
    assert!(dispatch(&json!({"op": "publication_prepare_request"})).unwrap()["error"].is_object());
}

#[test]
fn a_recovery_deadline_is_finite_and_at_most_a_minute_ahead() {
    let recovery = |deadline: Value| ask("recovery", json!({"deadline": deadline, "now": 100.0}));
    for ok in [json!(100.5), json!(160.0), json!(50.0)] {
        assert!(recovery(ok.clone()).is_ok(), "{ok}");
    }
    for bad in [json!(160.5), json!(true), json!("1"), Value::Null] {
        assert!(
            recovery(bad.clone())
                .unwrap_err()
                .contains("deadline_invalid"),
            "{bad}"
        );
    }
    assert!(ask("recovery", json!({"deadline": 110.0})).is_err());
}

#[test]
fn an_activation_runs_to_the_plan_expiry_or_the_callers_sooner_deadline() {
    let activation = |fields: Value| {
        let mut request = json!({"deadline_epoch": 1030.0, "wall": 1000.0, "now": 100.0});
        for (key, value) in fields.as_object().unwrap() {
            request[key] = value.clone();
        }
        ask("activation", request)
    };
    assert_eq!(activation(json!({})).unwrap()["deadline"], json!(130.0));
    assert_eq!(
        activation(json!({"deadline": null})).unwrap()["deadline"],
        json!(130.0)
    );
    assert_eq!(
        activation(json!({"deadline": 110.0})).unwrap()["deadline"],
        json!(110.0)
    );
    assert_eq!(
        activation(json!({"deadline": 900.0})).unwrap()["deadline"],
        json!(130.0)
    );
    // A plan already past its expiry gets no time at all.
    assert_eq!(
        activation(json!({"deadline_epoch": 900.0})).unwrap()["deadline"],
        json!(100.0)
    );
    for bad in [json!(true), json!("1")] {
        assert!(activation(json!({"deadline": bad}))
            .unwrap_err()
            .contains("deadline_invalid"));
    }
}
