//! Native request-context tests: parity vectors recorded from the Python
//! shell model, admission, request binding, and filesystem race behavior.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use guard_contracts::{
    RequestContextBuildV1, RequestContextExecutableV1, RequestContextKindV1,
    RequestContextPolicyV1, RequestContextRequestV1, RequestContextSourceV1, ShellContextV1,
    REQUEST_CONTEXT_REQUEST_SCHEMA, REQUEST_CONTEXT_SCHEMA,
};
use serde_json::{json, Value};

use super::{evaluate_request_context_request, request_digest, Budget};

const PARITY_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/fixtures/request-context-parity/cases.v1.json"
));

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn temp_root() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "rtm-request-context-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path.canonicalize().unwrap()
}

#[cfg(unix)]
fn owner() -> Option<u32> {
    Some(nix::unistd::geteuid().as_raw())
}

#[cfg(not(unix))]
fn owner() -> Option<u32> {
    None
}

fn request(action: RequestContextKindV1) -> RequestContextRequestV1 {
    RequestContextRequestV1 {
        schema: REQUEST_CONTEXT_REQUEST_SCHEMA.to_owned(),
        request_id: "request-context-test".to_owned(),
        guard_home: std::env::temp_dir()
            .join("guard-home")
            .to_string_lossy()
            .into_owned(),
        source: RequestContextSourceV1::Hook,
        budget_ms: 5_000,
        owner_uid: owner(),
        action,
    }
}

fn build_body(root: &Path, script: &str) -> RequestContextBuildV1 {
    RequestContextBuildV1 {
        workspace: Some(root.join("ws").to_string_lossy().into_owned()),
        cwd: Some(root.join("ws").to_string_lossy().into_owned()),
        script: Some(script.to_owned()),
        ..Default::default()
    }
}

fn run(request: &RequestContextRequestV1) -> Value {
    let bytes = evaluate_request_context_request(request).expect("response encodes");
    serde_json::from_slice(&bytes).unwrap()
}

fn payload_of(response: &Value) -> &Value {
    assert_eq!(response["status"], "ok", "{response}");
    &response["payload"]
}

fn code_of(request: &RequestContextRequestV1) -> String {
    let response = run(request);
    assert_eq!(response["status"], "error", "{response}");
    assert!(response["payload"].is_null());
    response["code"].as_str().unwrap().to_owned()
}

fn materialize(root: &Path, fs_spec: &Value) {
    for entry in fs_spec.as_array().unwrap() {
        let path = root.join(entry["path"].as_str().unwrap());
        match entry["kind"].as_str().unwrap() {
            "dir" => fs::create_dir_all(&path).unwrap(),
            "file" => fs::write(&path, "x").unwrap(),
            #[cfg(unix)]
            "symlink" => {
                std::os::unix::fs::symlink(entry["target"].as_str().unwrap(), &path).unwrap()
            }
            other => panic!("unknown fs kind {other}"),
        }
    }
}

fn rel(root: &Path, value: &Value) -> Value {
    let Some(text) = value.as_str() else {
        return Value::Null;
    };
    let root_text = root.to_string_lossy();
    if text == root_text {
        return json!("$ROOT");
    }
    match text.strip_prefix(&format!("{root_text}/")) {
        Some(rest) => json!(format!("$ROOT/{rest}")),
        None => json!(format!("$OUTSIDE:{text}")),
    }
}

fn identity_mode(value: &Value) -> Value {
    if value.is_null() {
        Value::Null
    } else {
        json!({"mode": value["mode"]})
    }
}

fn normalize_segment(root: &Path, segment: &Value) -> Value {
    json!({
        "tokens": segment["tokens"].as_array().unwrap().iter().map(|token| {
            json!(token.as_str().unwrap().replace(root.to_string_lossy().as_ref(), "$ROOT"))
        }).collect::<Vec<_>>(),
        "segment_index": segment["segment_index"],
        "control_before": segment["control_before"],
        "control_after": segment["control_after"],
        "effective_cwd": rel(root, &segment["effective_cwd"]),
        "cwd_identity": identity_mode(&segment["cwd_identity"]),
        "cwd_path_proofs": segment["cwd_path_proofs"].as_array().unwrap().iter().map(|proof| json!({
            "lexical_path": rel(root, &proof["lexical_path"]),
            "resolved_path": rel(root, &proof["resolved_path"]),
            "identity": identity_mode(&proof["identity"]),
        })).collect::<Vec<_>>(),
        "cwd_source": segment["cwd_source"],
        "directory_stack": segment["directory_stack"].as_array().unwrap().iter().map(|p| rel(root, p)).collect::<Vec<_>>(),
        "complete": segment["complete"],
        "reason_code": segment["reason_code"],
        "directory_operation": segment["directory_operation"],
    })
}

#[cfg(unix)]
#[test]
fn shell_model_matches_recorded_python_vectors() {
    let corpus: Value = serde_json::from_str(PARITY_FIXTURE).unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    assert!(cases.len() >= 30);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let root = temp_root();
        materialize(&root, &case["fs"]);
        let resolve = |key: &str| {
            case[key]
                .as_str()
                .map(|rel_path| root.join(rel_path).to_string_lossy().into_owned())
        };
        let script = case["command"]
            .as_str()
            .unwrap()
            .replace("{ROOT}", &root.to_string_lossy());
        let body = RequestContextBuildV1 {
            workspace: resolve("workspace"),
            cwd: resolve("cwd"),
            home_dir: resolve("home_dir"),
            script: Some(script),
            ..Default::default()
        };
        let response = run(&request(RequestContextKindV1::Build(body)));
        let report = &payload_of(&response)["shell"];
        let context = &report["context"];
        let expected = &case["expected"];
        assert_eq!(context["complete"], expected["complete"], "{name}");
        assert_eq!(context["reason_code"], expected["reason_code"], "{name}");
        assert_eq!(
            context["directory_change_present"], expected["directory_change_present"],
            "{name}"
        );
        assert_eq!(
            rel(&root, &context["initial_cwd"]),
            expected["initial_cwd"],
            "{name}"
        );
        assert_eq!(
            rel(&root, &context["workspace_root"]),
            expected["workspace_root"],
            "{name}"
        );
        assert_eq!(
            identity_mode(&context["workspace_identity"]),
            expected["workspace_identity"],
            "{name}"
        );
        let segments: Vec<Value> = context["segments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|segment| normalize_segment(&root, segment))
            .collect();
        assert_eq!(Value::Array(segments), expected["segments"], "{name}");
        let cwds: Vec<Value> = report["metadata"]["shell_execution_effective_cwds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|cwd| rel(&root, cwd))
            .collect();
        assert_eq!(Value::Array(cwds), expected["effective_cwds"], "{name}");
        let _ = fs::remove_dir_all(&root);
    }
}

#[test]
fn response_is_bound_to_the_canonical_request_digest() {
    let root = temp_root();
    fs::create_dir_all(root.join("ws")).unwrap();
    let req = request(RequestContextKindV1::Build(build_body(&root, "ls")));
    let response = run(&req);
    assert_eq!(response["request_id"], "request-context-test");
    assert_eq!(response["request_sha256"], request_digest(&req).unwrap());
    let payload = payload_of(&response);
    assert_eq!(payload["schema"], REQUEST_CONTEXT_SCHEMA);
    assert!(payload["context_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(payload["admission"]["source"], "hook");
    let mut other = req.clone();
    other.request_id = "different".to_owned();
    assert_ne!(
        request_digest(&other).unwrap(),
        request_digest(&req).unwrap()
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn admission_refuses_bad_owner_budget_schema_and_home() {
    let root = temp_root();
    fs::create_dir_all(root.join("ws")).unwrap();
    let base = request(RequestContextKindV1::Build(build_body(&root, "ls")));

    let mut bad = base.clone();
    bad.budget_ms = 0;
    assert_eq!(code_of(&bad), "native_request_context_budget_invalid");
    bad.budget_ms = guard_contracts::MAX_REQUEST_CONTEXT_BUDGET_MS + 1;
    assert_eq!(code_of(&bad), "native_request_context_budget_invalid");

    let mut bad = base.clone();
    bad.owner_uid = Some(u32::MAX - 1);
    assert_eq!(code_of(&bad), "native_request_context_owner_mismatch");
    #[cfg(unix)]
    {
        bad.owner_uid = None;
        assert_eq!(code_of(&bad), "native_request_context_owner_mismatch");
    }

    let mut bad = base.clone();
    bad.guard_home = "relative/home".to_owned();
    assert_eq!(code_of(&bad), "native_request_context_guard_home_invalid");

    let mut bad = base.clone();
    bad.schema = "guard-request-context-request.v0".to_owned();
    assert_eq!(
        evaluate_request_context_request(&bad).unwrap_err(),
        "native_request_context_schema_mismatch"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn policy_generation_must_match_the_snapshot() {
    let root = temp_root();
    fs::create_dir_all(root.join("ws")).unwrap();
    let snapshot = json!({"generation": 7, "policy_digest": "p", "rule_digest": "r"});
    let policy = |generation: u64, snapshot: &Value| {
        let mut body = build_body(&root, "ls");
        body.policy = Some(RequestContextPolicyV1 {
            generation,
            snapshot: snapshot.clone(),
        });
        request(RequestContextKindV1::Build(body))
    };
    assert_eq!(
        code_of(&policy(0, &snapshot)),
        "native_request_context_policy_generation_invalid"
    );
    assert_eq!(
        code_of(&policy(8, &snapshot)),
        "native_request_context_policy_generation_mismatch"
    );
    let ok = run(&policy(7, &snapshot));
    assert_eq!(payload_of(&ok)["admission"]["policy"]["generation"], 7);
    let first = payload_of(&ok)["context_sha256"].clone();
    let newer = json!({"generation": 8, "policy_digest": "p", "rule_digest": "r"});
    let moved = run(&policy(8, &newer));
    assert_ne!(first, payload_of(&moved)["context_sha256"]);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn expired_budget_fails_closed() {
    let budget = Budget {
        started: Instant::now()
            .checked_sub(Duration::from_secs(2))
            .unwrap_or_else(Instant::now),
        limit: Duration::from_millis(1),
    };
    assert_eq!(
        budget.check().unwrap_err(),
        "native_request_context_budget_exceeded"
    );
}

#[test]
fn missing_cwd_without_fallback_is_refused() {
    let body = RequestContextBuildV1 {
        script: Some("ls".to_owned()),
        ..RequestContextBuildV1::default()
    };
    assert_eq!(
        code_of(&request(RequestContextKindV1::Build(body))),
        "native_request_context_cwd_required"
    );
}

#[cfg(unix)]
#[test]
fn process_cwd_fallback_reports_the_process_source() {
    let root = temp_root();
    fs::create_dir_all(root.join("ws")).unwrap();
    let mut body = build_body(&root, "ls");
    body.cwd = None;
    body.fallback_cwd = Some(root.join("ws").to_string_lossy().into_owned());
    let response = run(&request(RequestContextKindV1::Build(body)));
    let segment = &payload_of(&response)["shell"]["context"]["segments"][0];
    assert_eq!(segment["cwd_source"], "process");
    let _ = fs::remove_dir_all(&root);
}

fn context_of(response: &Value) -> ShellContextV1 {
    serde_json::from_value(payload_of(response)["shell"]["context"].clone()).unwrap()
}

fn validate(context: &ShellContextV1, index: u64) -> Value {
    run(&request(RequestContextKindV1::ValidateSegment {
        context: context.clone(),
        segment_index: index,
    }))
}

#[cfg(unix)]
#[test]
fn swapped_directory_and_symlink_are_detected_after_modeling() {
    let root = temp_root();
    fs::create_dir_all(root.join("ws/inner")).unwrap();
    fs::create_dir_all(root.join("ws/other")).unwrap();
    std::os::unix::fs::symlink("inner", root.join("ws/link")).unwrap();
    let response = run(&request(RequestContextKindV1::Build(build_body(
        &root,
        "cd link && ls",
    ))));
    let context = context_of(&response);
    assert!(context.complete);

    let unchanged = validate(&context, 1);
    assert_eq!(unchanged["status"], "ok");
    assert!(unchanged["payload"]["reason_code"].is_null());
    assert_eq!(
        unchanged["payload"]["effective_cwd"],
        root.join("ws/inner").to_string_lossy().as_ref()
    );

    // Retarget the symlink between modeling and use.
    fs::remove_file(root.join("ws/link")).unwrap();
    std::os::unix::fs::symlink("other", root.join("ws/link")).unwrap();
    let swapped = validate(&context, 1);
    assert_eq!(swapped["payload"]["reason_code"], "shell_cwd_path_changed");
    assert!(swapped["payload"]["effective_cwd"].is_null());

    // Replace the resolved directory itself with a new inode.
    fs::remove_file(root.join("ws/link")).unwrap();
    std::os::unix::fs::symlink("inner", root.join("ws/link")).unwrap();
    fs::remove_dir(root.join("ws/inner")).unwrap();
    fs::create_dir(root.join("ws/inner")).unwrap();
    let replaced = validate(&context, 1);
    assert_eq!(replaced["payload"]["reason_code"], "shell_cwd_path_changed");
    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn forged_identity_or_completeness_never_grants_a_cwd() {
    let root = temp_root();
    fs::create_dir_all(root.join("ws/inner")).unwrap();
    let response = run(&request(RequestContextKindV1::Build(build_body(
        &root,
        "cd inner && ls",
    ))));
    let honest = context_of(&response);
    let honest_hash = payload_of(&response)["shell"]["context_hash"].clone();

    let mut forged = honest.clone();
    forged.segments[1].cwd_identity.as_mut().unwrap().inode += 1;
    assert_eq!(
        validate(&forged, 1)["payload"]["reason_code"],
        "shell_cwd_path_changed"
    );

    let mut escaped = honest.clone();
    escaped.segments[1].effective_cwd = Some(root.to_string_lossy().into_owned());
    assert!(validate(&escaped, 1)["payload"]["effective_cwd"].is_null());

    // A caller cannot supply a hash: it is recomputed from the claimed data.
    let recomputed = run(&request(RequestContextKindV1::Hash {
        context: forged,
        segment_index: Some(1),
    }));
    assert_ne!(payload_of(&recomputed)["context_hash"], honest_hash);
    let same = run(&request(RequestContextKindV1::Hash {
        context: honest,
        segment_index: None,
    }));
    assert_eq!(payload_of(&same)["context_hash"], honest_hash);

    let out_of_range = validate(&context_of(&response), 99);
    assert_eq!(out_of_range["status"], "error");
    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn launch_identity_binds_the_executable_and_argv() {
    let root = temp_root();
    fs::create_dir_all(root.join("ws")).unwrap();
    let script = root.join("ws/tool.sh");
    fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let with_args = |args: &[&str]| {
        let mut body = build_body(&root, "./tool.sh");
        body.executable = Some(RequestContextExecutableV1 {
            command: Some(json!(script.to_string_lossy())),
            args: args.iter().map(|arg| json!(arg)).collect(),
            structured_command: true,
            direct_executable: true,
            search_path: Some("/usr/bin:/bin".to_owned()),
            launch_env: None,
        });
        run(&request(RequestContextKindV1::Build(body)))
    };
    let first = with_args(&["one"]);
    let again = with_args(&["one"]);
    let second = with_args(&["two"]);
    assert!(payload_of(&first)["launch"].is_object());
    assert_eq!(
        payload_of(&first)["context_sha256"],
        payload_of(&again)["context_sha256"]
    );
    assert_ne!(
        payload_of(&first)["context_sha256"],
        payload_of(&second)["context_sha256"]
    );
    // Changing the script content changes the bound launch identity.
    fs::write(&script, "#!/bin/sh\nexit 1\n").unwrap();
    let edited = with_args(&["one"]);
    assert_ne!(
        payload_of(&first)["context_sha256"],
        payload_of(&edited)["context_sha256"]
    );
    let _ = fs::remove_dir_all(&root);
}
