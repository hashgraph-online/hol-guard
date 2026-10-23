//! Synthetic relation tests; these do not authenticate a live journal or
//! independently prove request-to-writer causality.

use gauntlet_contracts::canonicalize;
use gauntlet_evidence::StagingProductRelationPins;
use serde_json::{json, Value};

mod staging_relation_fixture;
use staging_relation_fixture::{fixture, public, sha, signed};

use gauntlet_contracts::{EffectFileHandle, EFFECT_IMAGE_JOURNAL_SCHEMA};
use gauntlet_evidence::{
    captured_contained_output, verify_staging_contained_relation_ineligible, ContainedFileIdentity,
};

fn digest(value: &Value) -> String {
    sha(&canonicalize(value.to_string().as_bytes()).unwrap())
}

struct ContainedFixture {
    builtin: Value,
    product: Value,
    journal: Value,
    file: ContainedFileIdentity,
}

impl ContainedFixture {
    fn raw(&self, role: &str) -> Vec<u8> {
        let plane = &self.builtin["product_plane"];
        let runtime = json!({"schema_version":"5.0","controller_session_id":role,
            "settings":{"source_sha":"b".repeat(40),
                "private_cell":{"native_sha256":"f".repeat(64)}},
            "native_builtin_audit":signed(self.builtin.clone())});
        json!({"developer_runtime":signed(runtime),"plane":plane})
            .to_string()
            .into_bytes()
    }

    // Rebind every signed copy, so refusal cannot be explained by a stale
    // digest when testing an internally consistent but wrong Native decision.
    fn replace_pre_response(&mut self, response: Value) {
        let digest = digest(&response);
        self.builtin["transport_observations"][0]["product_response"] = response.clone();
        self.builtin["transport_observations"][0]["response_digest"] = json!(digest);
        self.builtin["product_plane"]["hooks"][0]["response"] = response;
        self.builtin["product_plane"]["hooks"][0]["response_digest"] = json!(digest);
        self.builtin["contained_transport_observations"][0]["native_response_digest"] =
            json!(digest);
    }

    fn replace_post_response(&mut self, response: Value) {
        let digest = digest(&response);
        self.builtin["transport_observations"][2]["product_response"] = response.clone();
        self.builtin["transport_observations"][2]["response_digest"] = json!(digest);
        self.builtin["product_plane"]["hooks"][1]["response"] = response;
        self.builtin["product_plane"]["hooks"][1]["response_digest"] = json!(digest);
    }
}

fn contained_fixture(role: &str) -> ContainedFixture {
    let (mut plane, mut product) = fixture(role);
    let cgroup = format!(
        "/holgauntletrust{}.slice/hol-product-cell-{}.service",
        "a".repeat(16),
        "b".repeat(32)
    );
    product["cgroup"] = json!(cgroup);
    product["namespaces"]["user"] = json!({"device":4,"inode":106});
    plane["native_sha256"] = json!("f".repeat(64));
    let execution = json!({"exit_code":0,"stdout":"hello","stderr":"",
        "stdout_sha256":sha(b"hello"),"stderr_sha256":sha(b""),
        "payload_digest":"c".repeat(64),"request_sha256":"d".repeat(64)});
    let captured = captured_contained_output(&execution).unwrap();
    let pre_response = json!({"decision":"deny","policy_action":"sandbox-required",
        "required_execution_profile":"workspace-contained-v1","command_binding_digest":"4".repeat(64),
        "observe_mode":false});
    let post_response = json!({"decision":"allow","model_output_action":"allow_original",
        "reviewed_output_sha256":captured["output_sha256"]});
    let pre = json!({"sequence":1,"kind":"actual-hook-response","hook_event_name":"PreToolUse",
        "tool_call_id":"sdk-contained-control","tool_name":"bash","controller_session_id":role,
        "request_digest":"1".repeat(64),"original_input_digest":"3".repeat(64),
        "payload_digest":"c".repeat(64),"contained_route_issued":true,
        "product_response":pre_response,"response_digest":digest(&pre_response)});
    let post = json!({"sequence":3,"kind":"actual-hook-response","hook_event_name":"PostToolUse",
        "tool_call_id":"sdk-contained-control","tool_name":"bash","controller_session_id":role,
        "request_digest":"2".repeat(64),"original_input_digest":"3".repeat(64),
        "payload_digest":"d".repeat(64),"contained_route_issued":false,
        "actual_output_sha256":captured["output_sha256"],
        "product_response":post_response,"response_digest":digest(&post_response)});
    let binding = json!({"sequence":2,"kind":"actual-contained-output-binding",
        "tool_call_id":"sdk-contained-control","pre_payload_digest":"c".repeat(64),
        "payload_digest":"d".repeat(64),"result_digest":captured["result_digest"],
        "output_sha256":captured["output_sha256"],"sdk_output_sha256":"e".repeat(64),
        "schema":"controller-contained-output.v1"});
    plane["executions"] = json!([execution]);
    plane["hooks"] = json!([
        {"hook_event_name":"PreToolUse","payload_digest":pre["payload_digest"],
            "response_digest":pre["response_digest"],"response":pre_response,"returncode":0},
        {"hook_event_name":"PostToolUse","payload_digest":post["payload_digest"],
            "response_digest":post["response_digest"],"response":post_response,"returncode":0}
    ]);
    let builtin = json!({"product_plane":plane,"transport_observations":[pre,binding,post],
    "contained_transport_observations":[
        {"kind":"contained-route-prepared","token_digest":"5".repeat(64),
            "payload_digest":"c".repeat(64),"native_response_digest":digest(&pre_response)},
        {"kind":"contained-route-consumed","token_digest":"5".repeat(64),"payload_digest":"c".repeat(64)},
        {"kind":"actual-contained-result","token_digest":"5".repeat(64),"result_digest":captured["result_digest"]}
    ]});
    let handle = json!({"kind":1,"bytes":"a1b2c3d4e5f60718"});
    let namespaces = json!({"mnt":product["namespaces"]["mnt"],
        "pid":product["namespaces"]["pid"],"user":product["namespaces"]["user"]});
    let journal = json!({"schema":EFFECT_IMAGE_JOURNAL_SCHEMA,"run_id":"a".repeat(16),
        "source_sha":"b".repeat(40),"controller_public_key_hex":public(),
        "execution_eligible":false,"guard_causality_verified":false,
        "events":[{"sequence":1,"device":9,"inode":777,"file_handle":handle,
            "reported_pid":43,"pidfd_available":true,"owner":10004,
            "writer":{"pid":43,"start_ticks":124,"cgroup":cgroup}}],
        "writer_images":[{"event_sequence":1,"surface":"contained-output",
            "writer_pid":43,"writer_start_ticks":124,"unavailable_reason":null,
            "sample":{"executable_sha256":"f".repeat(64),"argv_sha256":"e".repeat(64),
                "observed_action":"serve-managed","uid":10004,"gid":10004,
                "namespace_pid":7,"parent_pid":42,"no_new_privileges":true,
                "seccomp_mode":2,"namespaces":namespaces}}]});
    ContainedFixture {
        builtin,
        product,
        journal,
        file: ContainedFileIdentity {
            device: 9,
            inode: 777,
            handle: EffectFileHandle::from_json(&handle).unwrap(),
        },
    }
}

fn contained_check(f: &ContainedFixture, role: &str) -> gauntlet_evidence::Result<Value> {
    verify_staging_contained_relation_ineligible(
        &f.raw(role),
        &StagingProductRelationPins {
            run_id: &"a".repeat(16),
            role,
            source_sha: &"b".repeat(40),
            controller_public_key_hex: &public(),
        },
        &f.product,
        &f.journal,
        &f.file,
        &"f".repeat(64),
    )
}

#[test]
fn four_positive_roles_compose_signed_routes_and_writer_without_a_causal_verdict() {
    for role in ["success", "input-binding", "injection", "boundary"] {
        let f = contained_fixture(role);
        let result = contained_check(&f, role).unwrap();
        assert_eq!(result["record_sha256"], sha(&f.raw(role)));
        assert_eq!(result["signed_routes_matched"], 1);
        assert_eq!(result["writer_relation"]["pid"], 43);
        assert_eq!(result["writer_relation"]["namespaces_matched"], 3);
        assert_eq!(
            result["writer_relation"]["executable_sha256"],
            "f".repeat(64)
        );
        for flag in [
            "request_to_writer_causality_verified",
            "guard_causality_verified",
            "execution_eligible",
        ] {
            assert_eq!(result[flag], false, "{role}: {flag}");
        }
    }
    for role in ["timeout", "cancel"] {
        assert!(contained_check(&contained_fixture(role), role).is_err());
    }
}

#[test]
fn consistently_resigned_wrong_native_decisions_and_transplanted_results_refuse() {
    for (field, value) in [
        ("decision", json!("allow")),
        ("policy_action", json!("allow")),
        ("required_execution_profile", json!("full-trust")),
        ("observe_mode", json!(true)),
        ("command_binding_digest", json!("invalid")),
    ] {
        let mut f = contained_fixture("success");
        let mut response = f.builtin["transport_observations"][0]["product_response"].clone();
        response[field] = value;
        f.replace_pre_response(response);
        assert!(contained_check(&f, "success").is_err(), "{field}");
    }
    for (field, value) in [
        ("decision", json!("deny")),
        ("model_output_action", json!("redact")),
        ("reviewed_output_sha256", json!("0".repeat(64))),
    ] {
        let mut f = contained_fixture("success");
        let mut response = f.builtin["transport_observations"][2]["product_response"].clone();
        response[field] = value;
        f.replace_post_response(response);
        assert!(contained_check(&f, "success").is_err(), "post: {field}");
    }
    for (path, value) in [
        ("/product_plane/native_sha256", json!("0".repeat(64))),
        ("/product_plane/executions/0/exit_code", json!(125)),
        (
            "/transport_observations/0/tool_call_id",
            json!("other-call"),
        ),
        (
            "/transport_observations/2/original_input_digest",
            json!("0".repeat(64)),
        ),
        ("/transport_observations/0/request_digest", json!("invalid")),
        (
            "/product_plane/hooks/0/response_digest",
            json!("0".repeat(64)),
        ),
        (
            "/contained_transport_observations/0/native_response_digest",
            json!("0".repeat(64)),
        ),
        (
            "/transport_observations/1/result_digest",
            json!("0".repeat(64)),
        ),
    ] {
        let mut f = contained_fixture("success");
        *f.builtin.pointer_mut(path).unwrap() = value;
        assert!(contained_check(&f, "success").is_err(), "{path}");
    }
}

#[test]
fn one_file_generation_cannot_hide_unknown_or_additional_matching_writes() {
    let mut f = contained_fixture("success");
    let mut other = f.journal["events"][0].clone();
    other["sequence"] = json!(2);
    other["file_handle"]["bytes"] = json!("0000000000000000");
    other["writer"] = Value::Null;
    other["pidfd_available"] = json!(false);
    f.journal["events"].as_array_mut().unwrap().push(other);
    // The opaque handle independently excludes a different object at a reused inode.
    assert!(contained_check(&f, "success").is_ok());
    f.journal["events"][1]["file_handle"] = Value::Null;
    assert!(contained_check(&f, "success").is_err());
    f.journal["events"][1]["file_handle"] = f.journal["events"][0]["file_handle"].clone();
    assert!(contained_check(&f, "success").is_err());
    let mut f = contained_fixture("success");
    f.file.inode += 1;
    assert!(contained_check(&f, "success").is_err());
    let mut f = contained_fixture("success");
    f.journal["events"][0]["writer"] = Value::Null;
    f.journal["writer_images"][0]["writer_start_ticks"] = Value::Null;
    f.journal["writer_images"][0]["sample"] = Value::Null;
    f.journal["writer_images"][0]["unavailable_reason"] = json!("writer-unavailable");
    assert!(contained_check(&f, "success").is_err());
}

#[test]
fn post_event_image_requires_native_asset_process_and_all_three_namespaces() {
    for (path, value) in [
        (
            "/writer_images/0/sample/executable_sha256",
            json!("0".repeat(64)),
        ),
        ("/writer_images/0/sample/observed_action", json!("other")),
        ("/writer_images/0/sample/namespace_pid", json!(1)),
        ("/writer_images/0/sample/namespaces/mnt/inode", json!(999)),
        ("/writer_images/0/sample/namespaces/pid/inode", json!(999)),
        ("/writer_images/0/sample/namespaces/user/inode", json!(999)),
        ("/writer_images/0/sample/uid", json!(0)),
        ("/events/0/writer/cgroup", json!("/different.slice/service")),
        ("/events/0/owner", json!(10001)),
    ] {
        let mut f = contained_fixture("success");
        *f.journal.pointer_mut(path).unwrap() = value;
        assert!(contained_check(&f, "success").is_err(), "{path}");
    }
    let mut f = contained_fixture("success");
    f.journal["events"][0]["writer"]["start_ticks"] = json!(122);
    f.journal["writer_images"][0]["writer_start_ticks"] = json!(122);
    assert!(contained_check(&f, "success").is_err());
    let mut f = contained_fixture("success");
    f.journal["writer_images"][0]["sample"] = Value::Null;
    f.journal["writer_images"][0]["unavailable_reason"] = json!("process-sample-unavailable");
    assert!(contained_check(&f, "success").is_err());
}

#[test]
fn run_schema_key_duplicates_and_eligibility_cannot_be_transplanted() {
    for (field, value) in [
        ("schema", json!("hol-gauntlet-staging-effect-events.v2")),
        ("run_id", json!("f".repeat(16))),
        ("source_sha", json!("f".repeat(40))),
        ("controller_public_key_hex", json!("0".repeat(64))),
        ("execution_eligible", json!(true)),
        ("guard_causality_verified", json!(true)),
    ] {
        let mut f = contained_fixture("success");
        f.journal[field] = value;
        assert!(contained_check(&f, "success").is_err(), "{field}");
    }
    for (path, index) in [
        ("/transport_observations", 0),
        ("/transport_observations", 1),
        ("/product_plane/executions", 0),
        ("/product_plane/hooks", 0),
        ("/contained_transport_observations", 0),
    ] {
        let mut f = contained_fixture("success");
        let rows = f.builtin.pointer_mut(path).unwrap().as_array_mut().unwrap();
        rows.push(rows[index].clone());
        assert!(contained_check(&f, "success").is_err(), "{path}:{index}");
    }
    let mut f = contained_fixture("success");
    f.journal["events"] = json!(vec![Value::Null; 32769]);
    assert!(contained_check(&f, "success").is_err());
}
