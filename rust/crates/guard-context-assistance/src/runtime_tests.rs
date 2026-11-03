use super::*;
use crate::inspect_bundle;

fn doctor() -> Value {
    json!({"capabilities": {
        "schema": "cigar.local-worker-capabilities.v1", "core_version": CIGAR_VERSION,
        "protocol": CIGAR_PROTOCOL, "execution": "isolated-process-serialized",
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

#[test]
fn platform_path_is_not_a_source_locator() {
    let selection = RuntimeSelection {
        verified_python: None,
        python_bundle: None,
        python: "/missing/python".into(),
        site_packages: "/missing/site-packages".into(),
        work_dir: "/missing/work".into(),
    };
    assert_eq!(
        inspect_bundle(&selection, "../../outside"),
        Err(RuntimeError::PlatformUnqualified)
    );
}

/// Run explicitly against the installed candidate, never silently claim that a
/// mocked worker qualifies the product. Only task-specific paths are read.
#[test]
#[ignore = "requires an explicitly staged CIGAR 0.14.1 bundle and CPython 3.14"]
fn installed_candidate_handshake_and_interpreter_refusal() {
    let selection_path =
        std::env::var_os("GUARD_CIGAR_TEST_SELECTION").expect("explicit test selection");
    let bytes = std::fs::read(selection_path).unwrap();
    let selection: RuntimeSelection = serde_json::from_slice(&bytes).unwrap();
    exercise_transport(&selection);
    let approval = inspect_bundle(&selection, "darwin-arm64").unwrap();
    let mut wrong = approval.clone();
    wrong.worker_sha256 = "0".repeat(64);
    assert!(matches!(
        VerifiedRuntime::start(selection.clone(), &wrong),
        Err(RuntimeError::ApprovalMismatch)
    ));
    let mut runtime = VerifiedRuntime::start(selection.clone(), &approval).unwrap();
    assert!(runtime.status().compile_verified);
    runtime.check_transport().unwrap();
    assert_eq!(runtime.status().interpreter.version[..2], [3, 14]);
    runtime.recheck_artifacts().unwrap();
    exercise_scoped_graph(&mut runtime);
    runtime.close();
    assert!(!runtime.status().active);
    assert_eq!(
        runtime
            .process
            .rpc(json!({"op": "doctor"}), Duration::from_secs(1)),
        Err(RuntimeError::RuntimeClosed)
    );

    let older =
        std::env::var_os("GUARD_CIGAR_TEST_OLDER_PYTHON").expect("explicit older interpreter");
    let mut older_selection = selection;
    older_selection.python = older.into();
    let older_approval = inspect_bundle(&older_selection, "darwin-arm64").unwrap();
    assert!(matches!(
        VerifiedRuntime::start(older_selection, &older_approval),
        Err(RuntimeError::Interpreter(
            UnavailableReason::PythonVersionUnsupported
        ))
    ));
    println!(
        "GUARD_CIGAR_VERIFICATION={}",
        json!({
            "schema": "guard-cigar-native-verification.v1", "status": "passed",
            "runtime_after_cleanup": runtime.status(), "bundle": approval,
            "checks": ["actual_isolated_interpreter", "package_fingerprint", "worker_handshake", "synthetic_compile_and_verify",
                "python_312_refused_before_sdk_import", "wrong_worker_approval_refused", "transport_id_mismatch_closed",
            "deadline_closed", "pending_transport_cancelled", "persistent_graph", "workspace_limit", "foreign_required_document_refused",
                "scoped_citations", "exact_large_revision_string", "out_of_scope_update_preserves_context",
                "readable_unselected_update_invalidates_context", "view_revocation", "empty_view_cannot_read_graph",
                "reopened_workspace_rejects_old_handle", "explicit_runtime_cleanup"],
            "qualification": "local-development-darwin-arm64-only",
            "verification_scope": "host-library-only"
        })
    );
}

fn exercise_transport(selection: &RuntimeSelection) {
    use std::time::Instant;
    let mut mismatched = JsonProcess::spawn(selection, "import sys,json\nfor line in sys.stdin:\n print(json.dumps({'schema':'guard-cigar-bridge.v1','id':0,'ok':True,'result':{}}),flush=True)").unwrap();
    assert_eq!(
        mismatched.rpc(json!({"op":"test"}), Duration::from_secs(1)),
        Err(RuntimeError::TransportFailed)
    );
    assert_eq!(
        mismatched.rpc(json!({"op":"test"}), Duration::from_secs(1)),
        Err(RuntimeError::RuntimeClosed)
    );
    let mut hung = JsonProcess::spawn(selection, "import time\ntime.sleep(60)").unwrap();
    let started = Instant::now();
    assert_eq!(
        hung.rpc(json!({"op":"test"}), Duration::from_millis(50)),
        Err(RuntimeError::DeadlineExceeded)
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(
        hung.rpc(json!({"op":"test"}), Duration::from_secs(1)),
        Err(RuntimeError::RuntimeClosed)
    );
    let cancel = Arc::new(AtomicBool::new(false));
    let mut cancelled = JsonProcess::spawn_cancellable(
        selection,
        "import time\ntime.sleep(60)",
        Arc::clone(&cancel),
    )
    .unwrap();
    let setter = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        cancel.store(true, Ordering::Release);
    });
    let started = Instant::now();
    assert_eq!(
        cancelled.rpc(json!({"op":"test"}), Duration::from_secs(3)),
        Err(RuntimeError::Cancelled)
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    setter.join().unwrap();
}

#[test]
fn cancelled_verification_is_refused_before_any_artifact_read_or_process_launch() {
    let selection = RuntimeSelection {
        verified_python: None,
        python_bundle: None,
        python: "/not-read/python".into(),
        site_packages: "/not-read/site".into(),
        work_dir: "/not-used/work".into(),
    };
    let approval: BundleApproval = serde_json::from_value(json!({"schema":"guard-cigar-bundle-approval.v1", "platform":"darwin-arm64", "python_sha256":"0".repeat(64), "package_tree_sha256":"0".repeat(64), "worker_sha256":"0".repeat(64), "files":1, "bytes":1})).unwrap();
    assert!(matches!(
        VerifiedRuntime::start_cancellable(selection, &approval, Arc::new(AtomicBool::new(true))),
        Err(RuntimeError::Cancelled)
    ));
}

fn exercise_scoped_graph(runtime: &mut VerifiedRuntime) {
    use crate::{ContextDocument, Limits};
    let doc = |id: &str, text: &str| ContextDocument {
        id: id.into(),
        text: text.into(),
        start_line: 1,
    };
    let limits = Limits {
        max_active_workspaces: 1,
        ..Limits::default()
    };
    let workspace = runtime.open_workspace("workspace-a", &limits).unwrap();
    assert!(matches!(
        runtime.open_workspace("workspace-b", &limits),
        Err(RuntimeError::ResourceLimit)
    ));
    runtime
        .replace_source(
            &workspace,
            "guard:policy",
            vec![doc(
                "policy",
                "Allow once and Always allow remain available.",
            )],
        )
        .unwrap();
    runtime
        .replace_source(
            &workspace,
            "other:source",
            vec![doc("private-other", "OUT_OF_SCOPE_CANARY")],
        )
        .unwrap();
    let view = runtime
        .create_view(
            &workspace,
            "app-a",
            ["guard:policy".into()].into(),
            "9007199254740993",
        )
        .unwrap();
    assert!(matches!(
        runtime.compile_context(&view, "OUT_OF_SCOPE_CANARY", vec!["private-other".into()]),
        Err(RuntimeError::ScopeDenied)
    ));
    let context = runtime
        .compile_context(&view, "approval", vec!["policy".into()])
        .unwrap();
    assert!(context.brief().rendered.contains("Always allow"));
    assert!(!context.brief().rendered.contains("OUT_OF_SCOPE_CANARY"));
    assert_eq!(context.brief().policy_revision, "9007199254740993");
    assert!(!context.brief().citations.is_empty());
    assert!(context.brief().rendered_tokens <= 1792);
    runtime.explain_context(&context).unwrap();
    runtime
        .replace_source(
            &workspace,
            "other:source",
            vec![doc("private-other", "OUT_OF_SCOPE_UPDATED")],
        )
        .unwrap();
    runtime.explain_context(&context).unwrap();
    // A change to any readable document invalidates, even if it was unselected.
    runtime
        .replace_source(
            &workspace,
            "guard:policy",
            vec![
                doc("policy", "Allow once and Always allow remain available."),
                doc("unselected", "Additional policy evidence."),
            ],
        )
        .unwrap();
    assert_eq!(
        runtime.explain_context(&context),
        Err(RuntimeError::ContextStale)
    );
    let refreshed = runtime
        .compile_context(&view, "approval", vec!["policy".into()])
        .unwrap();
    runtime.revoke_view(&view).unwrap();
    assert_eq!(
        runtime.explain_context(&refreshed),
        Err(RuntimeError::ScopeDenied)
    );
    let empty = runtime
        .create_view(&workspace, "empty", Default::default(), "same-policy")
        .unwrap();
    let empty_context = runtime
        .compile_context(&empty, "Always allow", vec![])
        .unwrap();
    assert!(empty_context.brief().citations.is_empty());
    assert!(!empty_context.brief().rendered.contains("Always allow"));
    runtime.close_workspace(&workspace).unwrap();
    let reopened = runtime.open_workspace("workspace-a", &limits).unwrap();
    assert!(matches!(
        runtime.replace_source(&workspace, "guard:policy", vec![]),
        Err(RuntimeError::ScopeDenied)
    ));
    runtime.close_workspace(&reopened).unwrap();
}
