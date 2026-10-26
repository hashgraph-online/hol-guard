//! Request-context resource bounds, absolute-path admission, and request
//! digest stability for omitted executable fields.

use std::time::{Duration, Instant};

use guard_contracts::{
    RequestContextBuildV1, RequestContextKindV1, RequestContextRequestV1, ShellContextV1,
    ShellPathIdentityV1, ShellPathProofV1, ShellSegmentV1, MAX_REQUEST_CONTEXT_SEGMENTS,
    MAX_REQUEST_CONTEXT_SEGMENT_PROOFS,
};
use serde_json::{json, Value};

use super::{canonical_digest, evaluate_request_context_request, request_digest, Budget};
use crate::request_context_shell as shell;

fn run(body: RequestContextBuildV1) -> Value {
    let request = RequestContextRequestV1 {
        schema: guard_contracts::REQUEST_CONTEXT_REQUEST_SCHEMA.to_owned(),
        request_id: "request-context-bounds".to_owned(),
        guard_home: std::env::temp_dir().to_string_lossy().into_owned(),
        source: guard_contracts::RequestContextSourceV1::Hook,
        budget_ms: 20_000,
        owner_uid: owner(),
        action: RequestContextKindV1::Build(body),
    };
    serde_json::from_slice(&evaluate_request_context_request(&request).unwrap()).unwrap()
}

#[cfg(unix)]
fn owner() -> Option<u32> {
    Some(nix::unistd::geteuid().as_raw())
}

#[cfg(not(unix))]
fn owner() -> Option<u32> {
    None
}

fn absolute() -> String {
    std::env::temp_dir().to_string_lossy().into_owned()
}

fn expired() -> Budget {
    Budget {
        started: Instant::now()
            .checked_sub(Duration::from_secs(5))
            .unwrap_or_else(Instant::now),
        limit: Duration::from_millis(1),
    }
}

fn live() -> Budget {
    Budget {
        started: Instant::now(),
        limit: Duration::from_secs(30),
    }
}

fn segment() -> ShellSegmentV1 {
    ShellSegmentV1 {
        tokens: vec!["ls".to_owned()],
        segment_index: 0,
        control_before: Vec::new(),
        control_after: Vec::new(),
        effective_cwd: Some(absolute()),
        cwd_identity: None,
        cwd_path_proofs: Vec::new(),
        cwd_source: "workspace".to_owned(),
        directory_stack: Vec::new(),
        complete: false,
        reason_code: Some("shell_cwd_path_changed".to_owned()),
        directory_operation: None,
    }
}

fn context(segments: Vec<ShellSegmentV1>) -> ShellContextV1 {
    ShellContextV1 {
        command_text: "ls".to_owned(),
        initial_cwd: None,
        workspace_root: None,
        workspace_identity: None,
        segments,
        complete: false,
        reason_code: Some("shell_cwd_path_changed".to_owned()),
        directory_change_present: false,
    }
}

#[test]
fn relative_paths_are_refused_instead_of_resolving_against_the_resident() {
    let base = || RequestContextBuildV1 {
        cwd: Some(absolute()),
        script: Some("ls".to_owned()),
        ..Default::default()
    };
    let mut variants = Vec::new();
    for field in ["cwd", "workspace", "home_dir", "fallback_cwd"] {
        let mut body = base();
        match field {
            "cwd" => body.cwd = Some(".".to_owned()),
            "workspace" => body.workspace = Some("ws".to_owned()),
            "home_dir" => body.home_dir = Some("~/home".to_owned()),
            _ => body.fallback_cwd = Some("../up".to_owned()),
        }
        variants.push(body);
    }
    for body in variants {
        let response = run(body);
        assert_eq!(
            response["code"], "native_request_context_path_not_absolute",
            "{response}"
        );
    }
}

#[test]
fn oversized_supplied_contexts_are_refused_before_conversion() {
    let too_many = context(vec![segment(); MAX_REQUEST_CONTEXT_SEGMENTS + 1]);
    let too_many_proofs = {
        let mut loaded = segment();
        loaded.cwd_path_proofs = vec![
            ShellPathProofV1 {
                lexical_path: absolute(),
                resolved_path: absolute(),
                identity: ShellPathIdentityV1 {
                    device: 1,
                    inode: 2,
                    mode: 3,
                    change_time_ns: 4,
                    creation_time_ns: 5,
                },
            };
            MAX_REQUEST_CONTEXT_SEGMENT_PROOFS + 1
        ];
        context(vec![loaded])
    };
    for oversized in [too_many, too_many_proofs] {
        assert_eq!(
            shell::hash_context(&oversized, None, &live()).unwrap_err(),
            "native_request_context_shell_too_large"
        );
        assert_eq!(
            shell::validate_segment(&oversized, 0, &live()).unwrap_err(),
            "native_request_context_shell_too_large"
        );
    }
}

#[test]
fn expired_budget_stops_validation_hashing_and_building_before_any_work() {
    let one = context(vec![segment()]);
    let code = "native_request_context_budget_exceeded";
    assert_eq!(
        shell::hash_context(&one, Some(0), &expired()).unwrap_err(),
        code
    );
    assert_eq!(
        shell::validate_segment(&one, 0, &expired()).unwrap_err(),
        code
    );
    assert_eq!(
        shell::build_shell_context("ls", Some(&absolute()), None, None, None, &expired())
            .unwrap_err(),
        code
    );
}

#[cfg(unix)]
#[test]
fn long_directory_change_chains_are_refused_not_modeled() {
    let dir = absolute();
    let body = |script: String| RequestContextBuildV1 {
        cwd: Some(dir.clone()),
        workspace: Some(dir.clone()),
        script: Some(script),
        ..Default::default()
    };
    let many_segments = "cd .;".repeat(MAX_REQUEST_CONTEXT_SEGMENTS + 1);
    assert_eq!(
        run(body(many_segments))["code"],
        "native_request_context_shell_too_large"
    );
    // Each `cd` extends the proof chain every later segment carries.
    let long_chain = "cd .;".repeat(1000);
    assert_eq!(
        run(body(long_chain))["code"],
        "native_request_context_shell_too_large"
    );
    assert_eq!(run(body("cd .; ls".to_owned()))["status"], "ok");
}

#[test]
fn partial_executable_claims_digest_like_their_defaulted_form() {
    let wire = |executable: Value| {
        json!({
            "schema": "guard-request-context-request.v1",
            "request_id": "digest-parity",
            "guard_home": absolute(),
            "source": "hook",
            "budget_ms": 1000,
            "owner_uid": null,
            "action": {"kind": "build", "body": {
                "policy": null, "workspace": null, "cwd": absolute(),
                "fallback_cwd": null, "home_dir": null, "script": null,
                "target": null, "executable": executable,
            }},
        })
    };
    let partial: RequestContextRequestV1 =
        serde_json::from_value(wire(json!({"command": "/bin/ls"}))).unwrap();
    let filled = wire(json!({
        "command": "/bin/ls", "args": [], "structured_command": false,
        "direct_executable": false, "search_path": null, "launch_env": null,
    }));
    assert_eq!(
        request_digest(&partial).unwrap(),
        canonical_digest(&filled).unwrap()
    );
    let omitted = wire(json!({"command": "/bin/ls"}));
    assert_ne!(
        request_digest(&partial).unwrap(),
        canonical_digest(&omitted).unwrap()
    );
}
