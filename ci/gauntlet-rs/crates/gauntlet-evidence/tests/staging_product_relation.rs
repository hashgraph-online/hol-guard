use base64::{engine::general_purpose::STANDARD, Engine};
use gauntlet_evidence::{verify_staging_product_relation_ineligible, StagingProductRelationPins};
use serde_json::{json, Value};

mod staging_relation_fixture;
use staging_relation_fixture::{fixture, public, sha, signed};

fn record(plane: &Value, role: &str) -> Vec<u8> {
    let runtime = json!({"schema_version":"5.0","controller_session_id":role,
        "settings":{"source_sha":"b".repeat(40)},
        "native_builtin_audit":signed(json!({"product_plane":plane}))});
    json!({"developer_runtime":signed(runtime),"plane":plane})
        .to_string()
        .into_bytes()
}
fn check(raw: &[u8], sample: &Value, role: &str) -> gauntlet_evidence::Result<Value> {
    verify_staging_product_relation_ineligible(
        raw,
        &StagingProductRelationPins {
            run_id: &"a".repeat(16),
            role,
            source_sha: &"b".repeat(40),
            controller_public_key_hex: &public(),
        },
        sample,
    )
}

#[test]
fn all_six_roles_bind_signatures_process_and_three_task_maps() {
    for role in [
        "success",
        "input-binding",
        "injection",
        "boundary",
        "timeout",
        "cancel",
    ] {
        let (plane, sample) = fixture(role);
        let raw = record(&plane, role);
        let result = check(&raw, &sample, role).unwrap();
        assert_eq!(result["record_sha256"], sha(&raw));
        assert_eq!(result["task_mounts_matched"], 3);
        assert_eq!(result["namespaces_matched"], 6);
        assert_eq!(result["guard_causality_verified"], false);
        assert_eq!(result["execution_eligible"], false);
    }
}

#[test]
fn signed_but_false_process_mount_or_run_claims_refuse() {
    let (plane, sample) = fixture("success");
    for (path, value) in [
        ("/source_sha", json!("d".repeat(40))),
        ("/cell_observations/1/identity/pid", json!(43)),
        ("/cell_observations/1/identity/start_time", json!("124")),
        (
            "/cell_observations/1/identity/namespaces/mnt",
            json!("mnt:[900]"),
        ),
        (
            "/cell_observations/1/identity/argv/3",
            json!("/public/other.py"),
        ),
        (
            "/cell_observations/1/identity/argv/3",
            json!("/public/actor.py\0hidden"),
        ),
        ("/cell_observations/1/identity/status/Uid", json!("0 0 0 0")),
        ("/cell_observations/1/identity/status/NSpid", json!("42 2")),
        ("/cell_observations/1/identity/status/Seccomp", json!("0")),
        ("/cell_observations/1/identity/mountinfo", json!("changed")),
        ("/cell_observations/0/mounts/0/observer_pid", json!(43)),
        (
            "/cell_observations/0/mounts/0/product_view/uid",
            json!(10001),
        ),
        (
            "/cell_observations/0/declaration_digest",
            json!("d".repeat(64)),
        ),
        (
            "/task_mounts/0/source",
            json!("/home/hx-ffffffffffffffff/success/tasks/checkout"),
        ),
    ] {
        let mut changed = plane.clone();
        *changed.pointer_mut(path).unwrap() = value;
        assert!(
            check(&record(&changed, "success"), &sample, "success").is_err(),
            "{path}"
        );
    }
    let mut duplicate = plane.clone();
    duplicate["cell_observations"]
        .as_array_mut()
        .unwrap()
        .push(plane["cell_observations"][1].clone());
    assert!(check(&record(&duplicate, "success"), &sample, "success").is_err());
    assert!(check(&record(&plane, "boundary"), &sample, "success").is_err());
    // A producer can sign a consistent substitute map; the kernel pin still refuses it.
    let mut forged = plane.clone();
    forged["task_mounts"][0]["inode"] = json!(900);
    for view in ["physical", "product_view"] {
        forged["cell_observations"][0]["mounts"][0][view]["inode"] = json!(900);
    }
    assert!(check(&record(&forged, "success"), &sample, "success").is_err());
}

#[test]
fn signatures_outside_key_and_independent_sample_are_required() {
    let (plane, sample) = fixture("success");
    let raw = record(&plane, "success");
    let mut bad: Value = serde_json::from_slice(&raw).unwrap();
    bad["developer_runtime"]["record"]["controller_session_id"] = json!("boundary");
    assert!(check(bad.to_string().as_bytes(), &sample, "success").is_err());
    let mut unsigned_inner = bad["developer_runtime"]["record"].clone();
    unsigned_inner["controller_session_id"] = json!("success");
    unsigned_inner["native_builtin_audit"]["signature"] = json!(STANDARD.encode([0u8; 64]));
    bad["developer_runtime"] = signed(unsigned_inner);
    assert!(check(bad.to_string().as_bytes(), &sample, "success").is_err());
    for (path, value) in [
        ("/pid", json!(43)),
        ("/pid", json!(true)),
        ("/start_ticks", json!(124)),
        ("/task_mounts/1/inode", json!(999)),
        ("/task_mounts/2/product_uid", json!(10001)),
        ("/argv_sha256", json!("e".repeat(64))),
        ("/mountinfo_sha256", json!("e".repeat(64))),
    ] {
        let mut changed = sample.clone();
        *changed.pointer_mut(path).unwrap() = value;
        assert!(check(&raw, &changed, "success").is_err(), "{path}");
    }
    let mut duplicate = sample.clone();
    duplicate["task_mounts"][2] = sample["task_mounts"][1].clone();
    assert!(check(&raw, &duplicate, "success").is_err());
    for pins in [
        StagingProductRelationPins {
            run_id: "aaaaaaaaaaaaaaaa",
            role: "success",
            source_sha: &"b".repeat(40),
            controller_public_key_hex: &"0".repeat(64),
        },
        StagingProductRelationPins {
            run_id: "aaaaaaaaaaaaaa/.",
            role: "success",
            source_sha: &"b".repeat(40),
            controller_public_key_hex: &public(),
        },
    ] {
        assert!(verify_staging_product_relation_ineligible(&raw, &pins, &sample).is_err());
    }
}
