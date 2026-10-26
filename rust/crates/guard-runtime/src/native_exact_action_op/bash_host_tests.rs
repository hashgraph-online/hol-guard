use super::*;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

fn intended(root: &Path) -> NativeBashCaptureV1 {
    NativeBashCaptureV1 {
        harness: "omp".into(),
        command: "/bin/bash script.sh dry".into(),
        cwd: "/old/hook/cwd".into(),
        workspace: root.to_str().unwrap().into(),
        home_dir: "/old/hook/home".into(),
        guard_home: root.join("guard").to_str().unwrap().into(),
        execution_environment: GuardExecutionEnvironmentV1::unavailable(),
        environment: BTreeMap::from([("LANG".into(), "old-locale".into())]),
        file_creation_mask: Some(0),
        budget_ms: 1000,
    }
}

fn environment(root: &Path) -> Vec<(OsString, OsString)> {
    vec![
        ("HOME".into(), root.into()),
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("LANG".into(), "en_US.UTF-8".into()),
        ("UNRELATED_PRIVATE_VALUE".into(), "withheld".into()),
    ]
}

#[test]
fn bash_final_host_context_replaces_hook_values_without_exposing_unrelated_exports() {
    let root = tempfile::tempdir().unwrap();
    let intended = intended(root.path());
    let original = restamp(&intended, root.path(), environment(root.path())).unwrap();
    assert_eq!(original.cwd, root.path().to_str().unwrap());
    assert_eq!(original.home_dir, root.path().to_str().unwrap());
    assert_eq!(original.command, intended.command);
    assert_eq!(original.guard_home, intended.guard_home);
    assert_eq!(original.workspace, intended.workspace);
    assert_eq!(original.file_creation_mask, None);
    assert_eq!(
        original.environment,
        BTreeMap::from([("LANG".into(), "en_US.UTF-8".into())])
    );
    assert!(!serde_json::to_string(&original)
        .unwrap()
        .contains("withheld"));
    let mut changed = environment(root.path());
    changed.last_mut().unwrap().1 = "another-private-value".into();
    assert_eq!(restamp(&intended, root.path(), changed).unwrap(), original);
    let mut startup = environment(root.path());
    startup.push(("BASH_ENV".into(), "/unobserved/startup.sh".into()));
    let stamp = restamp(&intended, root.path(), startup).unwrap();
    assert!(stamp
        .execution_environment
        .environment_names
        .iter()
        .any(|name| name == "BASH_ENV"));
    assert!(!stamp.environment.contains_key("BASH_ENV"));
}

#[test]
fn bash_final_host_environment_refuses_ambiguous_and_unencodable_required_values() {
    let root = tempfile::tempdir().unwrap();
    let request = intended(root.path());
    let mut duplicate = environment(root.path());
    duplicate.push(("LANG".into(), "C".into()));
    assert!(restamp(&request, root.path(), duplicate).is_err());
    for malformed in [
        OsString::from_vec(vec![0xff]),
        OsString::from("x".repeat(32 * 1024 + 1)),
    ] {
        let mut values = environment(root.path());
        values[2].1 = malformed;
        assert!(restamp(&request, root.path(), values).is_err());
    }
    let mut values = environment(root.path());
    values.push((OsString::from_vec(vec![0xff]), "value".into()));
    assert!(restamp(&request, root.path(), values).is_err());
    assert!(restamp(&request, root.path(), [("PATH".into(), "/bin".into())]).is_err());
}

#[test]
fn bash_creation_mask_probe_is_read_only_and_preserves_the_parent_mask() {
    let root = tempfile::tempdir().unwrap();
    let cwd = root.path().canonicalize().unwrap();
    let before = root.path().join("before");
    std::fs::write(&before, b"control").unwrap();
    let parent_mode = std::fs::metadata(&before).unwrap().permissions().mode() & 0o777;
    let mask = creation_mask(
        &cwd,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(parent_mode, 0o666 & !mask);
    let after = root.path().join("after");
    std::fs::write(&after, b"control").unwrap();
    assert_eq!(
        std::fs::metadata(after).unwrap().permissions().mode() & 0o777,
        parent_mode
    );
    assert!(creation_mask(
        &cwd,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(true)
    )
    .is_err());
}

#[test]
fn bash_creation_mask_probe_refuses_truncated_or_malformed_output() {
    for (bytes, expected) in [
        (b"0022\n".as_slice(), 0o022),
        (b"077\n", 0o077),
        (b"0002\n", 0o002),
    ] {
        assert_eq!(parse_mask(bytes).unwrap(), expected);
    }
    for bytes in [
        b"022".as_slice(),
        b"08\n",
        b"1000\n",
        b"22\n",
        b"0022\nextra",
        b"0022\n\n",
        b"\xff\n",
    ] {
        assert!(parse_mask(bytes).is_err());
    }
}

#[test]
fn bash_native_sink_observes_the_current_process_and_actual_mask() {
    let root = tempfile::tempdir().unwrap();
    let observed = observe_current(
        &intended(root.path()),
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(
        Path::new(&observed.cwd),
        std::env::current_dir().unwrap().canonicalize().unwrap()
    );
    assert_eq!(observed.home_dir, std::env::var("HOME").unwrap());
    assert!(observed.file_creation_mask.is_some());
    assert!(observed.execution_environment.has_valid_shape());
}

#[test]
fn bash_host_cli_contract_observes_actual_context_and_rejects_unknown_versions() {
    use guard_contracts::{
        NativeBashHostRequestV1, NativeBashHostResultV1, NATIVE_BASH_HOST_REQUEST_SCHEMA,
    };
    let root = tempfile::tempdir().unwrap();
    let mut request = NativeBashHostRequestV1 {
        schema: NATIVE_BASH_HOST_REQUEST_SCHEMA.into(),
        request_id: "host-context-test".into(),
        capture: intended(root.path()),
        budget_ms: 1000,
    };
    let evaluate = |request: &NativeBashHostRequestV1| -> NativeBashHostResultV1 {
        serde_json::from_slice(
            &super::super::bash_route::observe_host_bytes(&serde_json::to_vec(request).unwrap())
                .unwrap(),
        )
        .unwrap()
    };
    let result = evaluate(&request);
    assert_eq!(result.status, "ok");
    let capture = result.payload.unwrap();
    assert_ne!(capture.cwd, request.capture.cwd);
    assert_ne!(capture.home_dir, request.capture.home_dir);
    assert!(capture.file_creation_mask.is_some());
    assert!(
        !root.path().join("guard").exists(),
        "observation creates no Guard state"
    );
    request.schema = "guard-native-bash-host-request.v99".into();
    let refused = evaluate(&request);
    assert_eq!(refused.status, "error");
    assert!(refused.payload.is_none());
    let mut unknown = serde_json::to_value(&request).unwrap();
    unknown["allow"] = serde_json::Value::Bool(true);
    assert!(
        super::super::bash_route::observe_host_bytes(&serde_json::to_vec(&unknown).unwrap())
            .is_err()
    );
}
