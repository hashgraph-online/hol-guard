use super::*;
use guard_contracts::{
    GuardExecutionEnvironmentV1, NativeExactActionPayloadV1, NativeExactActionQueryV1,
    NativeExactActionRequestV1, NativeExactActionResultV1, NATIVE_EXACT_ACTION_REQUEST_SCHEMA,
};

const SCRIPT: &str = include_str!("../../../../../tests/fixtures/script_approvals/maintenance.sh");
const HELPER: &str =
    include_str!("../../../../../tests/fixtures/script_approvals/fixture-registry");

#[path = "bash_review_descriptor_tests.rs"]
mod review_descriptor_tests;

pub(super) fn admitted(default: &str) -> crate::policy_enforcement::AdmittedPolicySnapshot {
    use crate::policy_enforcement::tests::{policy, snapshot};
    crate::policy_enforcement::AdmittedPolicySnapshot::new(snapshot(policy(default))).unwrap()
}

pub(super) fn fixture() -> (tempfile::TempDir, NativeBashCaptureV1) {
    let root = tempfile::Builder::new()
        .prefix("guard-bash-fixture-")
        .tempdir()
        .unwrap();
    let project = root.path().canonicalize().unwrap();
    let home = project.join("home");
    let guard_home = project.join("guard");
    std::fs::create_dir(&home).unwrap();
    std::fs::create_dir(&guard_home).unwrap();
    let entry = project.join("maintenance.sh");
    let helper = project.join("fixture-registry");
    std::fs::write(&entry, SCRIPT).unwrap();
    std::fs::write(&helper, HELPER).unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let request = NativeBashCaptureV1 {
        harness: "omp".into(),
        command: format!("/bin/bash '{}' dry", entry.display()),
        cwd: text(&project).unwrap(),
        workspace: text(&project).unwrap(),
        home_dir: text(&home).unwrap(),
        guard_home: text(&guard_home).unwrap(),
        execution_environment: GuardExecutionEnvironmentV1 {
            path: format!("{}:/usr/bin:/bin", project.display()),
            environment_names: vec!["HOME".into(), "PATH".into()],
            environment_digest: "a".repeat(64),
            home: Some(text(&home).unwrap()),
            ..GuardExecutionEnvironmentV1::unavailable()
        },
        environment: BTreeMap::new(),
        file_creation_mask: Some(0o022),
        budget_ms: super::super::ANALYSIS_BUDGET_CAP_MS,
    };
    (root, request)
}

#[test]
fn bash_launch_capture_holds_native_inputs_without_touching_the_report() {
    let (_root, request) = fixture();
    let report_path = Path::new(&request.home_dir).join("maintenance-report.tsv");
    std::fs::write(&report_path, "existing report").unwrap();
    let inspected = inspect(&request).unwrap();
    let captured = capture_for_launch(&request, &admitted("allow")).unwrap();
    assert_eq!(
        inspected.identity_sha256().unwrap(),
        captured.subject.identity_sha256().unwrap()
    );
    assert!(captured.graph.source_for_launch().unwrap().contains(">&7"));
    assert_eq!(
        captured.policy.as_ref().unwrap().decisions.len(),
        1 + captured.graph.invocations.len() + captured.graph.writes.len()
    );
    assert!(captured.interpreter.has_readonly_system_image().unwrap());
    assert_eq!(captured.environment.get("HOME"), Some(&request.home_dir));
    let target = captured.report.unwrap();
    target.directory.verify().unwrap();
    assert_eq!(target.leaf, "maintenance-report.tsv");
    assert!(!target.append);
    assert_eq!(
        std::fs::read_to_string(report_path).unwrap(),
        "existing report"
    );
}

#[test]
fn bash_launch_capture_rejects_late_report_preparation() {
    let (_root, request) = fixture();
    std::fs::write(
        Path::new(&request.cwd).join("maintenance.sh"),
        "set -euo pipefail; false; : > \"$HOME/report.tsv\"",
    )
    .unwrap();
    assert!(inspect(&request).is_ok());
    assert!(matches!(
        capture_for_launch(&request, &admitted("allow")),
        Err(reason) if reason == "bash_output_timing_unproven"
    ));
    assert!(!Path::new(&request.home_dir).join("report.tsv").exists());
}

#[test]
fn bash_launch_capture_rechecks_policy_without_mutating_outputs() {
    let (_root, request) = fixture();
    let initial = capture_for_launch(&request, &admitted("allow")).unwrap();
    assert!(initial
        .policy
        .as_ref()
        .unwrap()
        .decisions
        .iter()
        .all(|decision| decision.minimum_action == "allow"));
    assert!(
        matches!(capture_for_launch(&request, &admitted("block")), Err(reason) if reason == "bash_current_policy_denied")
    );
    let graph = &initial.graph;
    let blocked = super::super::super::bash_policy::assess(
        graph,
        &request,
        &admitted("block"),
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    assert!(blocked.has_hard_deny());
    assert_eq!(
        blocked.decisions.len(),
        1 + graph.invocations.len() + graph.writes.len()
    );
    assert!(blocked
        .decisions
        .iter()
        .all(|decision| decision.minimum_action == "block"));
    assert!(!Path::new(&request.home_dir)
        .join("maintenance-report.tsv")
        .exists());
}

#[test]
fn bash_resident_inspection_preserves_helper_execution_spelling() {
    let (_root, request) = fixture();
    let cwd = Path::new(&request.cwd);
    let home = Path::new(&request.home_dir);
    let mut environment = environment(&request).unwrap();
    environment.insert("PATH".into(), ":/usr/bin:/bin".into());
    let resolver = Resolver {
        cwd,
        home,
        environment: &environment,
        names: &[],
        deadline: Instant::now() + Duration::from_secs(1),
        captured: RefCell::new(BTreeMap::new()),
        brokered_commands: RefCell::new(Vec::new()),
        source_snapshots: RefCell::new(BTreeMap::new()),
        source_contents: RefCell::new(BTreeMap::new()),
        network_destinations: RefCell::new(BTreeSet::new()),
    };
    let graph::Executable::Bash(helper) = graph::Resolver::resolve(
        &resolver,
        &["./fixture-registry".into(), "list".into(), "alpha".into()],
    )
    .unwrap() else {
        panic!("expected captured Bash source");
    };
    assert_eq!(helper.original_path, "./fixture-registry");
    assert_eq!(
        helper.resolved_path,
        text(&cwd.join("fixture-registry")).unwrap()
    );
    let graph::Executable::Bash(helper) = graph::Resolver::resolve(
        &resolver,
        &["fixture-registry".into(), "list".into(), "alpha".into()],
    )
    .unwrap() else {
        panic!("expected captured Bash source");
    };
    assert_eq!(helper.original_path, "./fixture-registry");
}

#[test]
fn bash_resident_inspection_captures_nonexecutable_source_and_reevaluates_changes() {
    let (_root, request) = fixture();
    let project = Path::new(&request.cwd);
    std::fs::write(
        project.join("maintenance.sh"),
        "source ./settings.sh; printf '%s' \"$from_source\"",
    )
    .unwrap();
    let settings = project.join("settings.sh");
    std::fs::write(&settings, "from_source=reviewed").unwrap();
    std::fs::set_permissions(&settings, std::fs::Permissions::from_mode(0o600)).unwrap();
    let original = inspect(&request).unwrap();
    assert!(original
        .code_inputs
        .iter()
        .any(|input| input.kind == NativeScriptInputKindV1::Source));
    assert!(original
        .invocations
        .iter()
        .any(|call| call.argv == ["printf", "%s", "reviewed"]));
    std::fs::write(&settings, "from_source=changed").unwrap();
    let changed = inspect(&request).unwrap();
    assert_ne!(
        original.identity_sha256().unwrap(),
        changed.identity_sha256().unwrap()
    );
    assert!(changed
        .invocations
        .iter()
        .any(|call| call.argv == ["printf", "%s", "changed"]));
}

#[test]
fn bash_resident_inspection_captures_real_fixture_without_permission_token() {
    let (_root, mut capture) = fixture();
    let request = NativeExactActionRequestV1 {
        schema: NATIVE_EXACT_ACTION_REQUEST_SCHEMA.into(),
        request_id: "capture-fixture".into(),
        query: NativeExactActionQueryV1::BashSubject {
            capture: Box::new(capture.clone()),
        },
    };
    assert!(crate::resident_protocol::capabilities()
        .features
        .contains(&guard_contracts::NATIVE_BASH_SUBJECT_INSPECTION_FEATURE.to_owned()));
    let wrapped = serde_json::json!({"operation": "native_exact_action", "request": request});
    let bytes = crate::resident_protocol::evaluate_resident_bytes(
        &serde_json::to_vec(&wrapped).unwrap(),
        None,
    )
    .unwrap();
    let result: NativeExactActionResultV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.status, "ok");
    let NativeExactActionPayloadV1::BashSubject {
        subject,
        unavailable_reason,
    } = result.payload.unwrap()
    else {
        panic!("inspection returned another operation's authority");
    };
    assert!(unavailable_reason.is_none(), "{unavailable_reason:?}");
    let subject = subject.unwrap();
    assert_eq!(subject.code_inputs.len(), 5);
    assert_eq!(subject.outputs.len(), 5);
    assert_eq!(subject.argv[1], "dry");
    assert!(!Path::new(&subject.outputs[0].resolved_path).exists());
    assert!(subject.identity_sha256().is_ok());
    // A changed opaque commitment to unrelated host values is not code drift.
    capture.execution_environment.environment_digest = "b".repeat(64);
    assert_eq!(
        subject.identity_sha256().unwrap(),
        inspect(&capture).unwrap().identity_sha256().unwrap()
    );
}

#[test]
fn bash_resident_inspection_never_treats_withheld_exports_as_unset() {
    let (_root, mut request) = fixture();
    let entry = Path::new(&request.cwd).join("maintenance.sh");
    for source in [
        "printf '%s' \"${mode:-dry}\"",
        "mode=dry; printf '%s' \"$mode\"",
        "for mode in dry; do printf '%s' \"$mode\"; done",
        ". ./settings.sh",
    ] {
        std::fs::write(&entry, source).unwrap();
        std::fs::write(
            Path::new(&request.cwd).join("settings.sh"),
            "printf '%s' \"${mode:-dry}\"",
        )
        .unwrap();
        let absent = inspect(&request).unwrap();
        request
            .execution_environment
            .environment_names
            .push("unrelated_export".into());
        assert_eq!(
            absent.identity_sha256().unwrap(),
            inspect(&request).unwrap().identity_sha256().unwrap()
        );
        request.execution_environment.environment_names.pop();
        request
            .execution_environment
            .environment_names
            .push("mode".into());
        assert!(
            matches!(
                inspect(&request),
                Err("bash_exported_environment_value_withheld"
                    | "bash_exported_environment_assignment_unproven")
            ),
            "accepted {source}"
        );
        request.execution_environment.environment_names.pop();
    }
}

#[test]
fn bash_resident_inspection_rejects_crlf_helper_interpreter_spelling() {
    let (_root, request) = fixture();
    std::fs::write(
        Path::new(&request.cwd).join("fixture-registry"),
        "#!/bin/bash\r\nprintf changed\n",
    )
    .unwrap();
    assert_eq!(inspect(&request), Err("bash_helper_interpreter_unproven"));
}

#[test]
fn bash_resident_inspection_refuses_host_process_descriptor_sources() {
    use std::os::fd::AsRawFd;
    let (_root, mut request) = fixture();
    let path = Path::new(&request.cwd).join("maintenance.sh");
    let source = std::fs::File::open(&path).unwrap();
    request.command = format!("/bin/bash /dev/fd/{} dry", source.as_raw_fd());
    assert_eq!(inspect(&request), Err("bash_process_descriptor_unproven"));
    std::fs::write(&path, format!("source /dev/fd/{}", source.as_raw_fd())).unwrap();
    request.command = format!("/bin/bash '{}' dry", path.display());
    assert_eq!(inspect(&request), Err("bash_process_descriptor_unproven"));
}

#[test]
fn bash_resident_inspection_rejects_unbindable_report_targets_without_mutation() {
    let (_root, request) = fixture();
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    let protected = Path::new(&request.home_dir).join("protected-output");
    std::fs::write(&protected, "protected sentinel").unwrap();
    std::os::unix::fs::symlink(&protected, &report).unwrap();
    assert_eq!(inspect(&request), Err("bash_output_target_unavailable"));
    assert_eq!(
        std::fs::read_to_string(&protected).unwrap(),
        "protected sentinel"
    );
    std::fs::remove_file(&report).unwrap();
    std::fs::hard_link(&protected, &report).unwrap();
    assert_eq!(inspect(&request), Err("bash_output_target_unavailable"));
    assert_eq!(
        std::fs::read_to_string(&protected).unwrap(),
        "protected sentinel"
    );
    std::fs::remove_file(&report).unwrap();
    std::fs::create_dir(&report).unwrap();
    assert_eq!(inspect(&request), Err("bash_output_target_unavailable"));
    std::fs::remove_dir(&report).unwrap();
    let entry = Path::new(&request.cwd).join("maintenance.sh");
    for target in ["/dev/stdout", "/dev/stderr", "/dev/fd/6", "/proc/self/fd/6"] {
        std::fs::write(&entry, format!(": > '{target}'")).unwrap();
        assert_eq!(inspect(&request), Err("bash_process_descriptor_unproven"));
    }
    for suffix in ["/", "/.", "/.."] {
        std::fs::write(&entry, format!(": > \"$HOME/report{suffix}\"")).unwrap();
        assert_eq!(inspect(&request), Err("bash_output_path_invalid"));
        assert!(!Path::new(&request.home_dir).join("report").exists());
    }
}

#[test]
fn bash_resident_inspection_refuses_all_exported_function_encodings() {
    let (_root, mut request) = fixture();
    for name in ["BASH_FUNC_printf%%", "__BASH_FUNC<printf>()"] {
        request
            .execution_environment
            .environment_names
            .push(name.into());
        assert_eq!(inspect(&request), Err("bash_startup_environment_unproven"));
        request.execution_environment.environment_names.pop();
    }
    request
        .execution_environment
        .environment_names
        .push("LANG".into());
    request
        .environment
        .insert("LANG".into(), "() { printf hidden; }".into());
    assert_eq!(inspect(&request), Err("bash_startup_environment_unproven"));
}

#[test]
fn bash_resident_inspection_preserves_interpreter_mode_and_script_option_boundary() {
    let (_root, mut request) = fixture();
    let project = Path::new(&request.cwd);
    let alias = project.join("sh");
    std::os::unix::fs::symlink("/bin/bash", &alias).unwrap();
    request.command = format!(
        "'{}' '{}' dry",
        alias.display(),
        project.join("maintenance.sh").display()
    );
    assert_eq!(inspect(&request), Err("bash_interpreter_spelling_unproven"));
    std::fs::write(project.join("+e"), "printf unintended").unwrap();
    request.command = "/bin/bash +e dry".into();
    assert_eq!(inspect(&request), Err("bash_invocation_options_unproven"));
}

#[test]
fn bash_resident_inspection_shares_alias_bytes_and_obeys_effective_execute_access() {
    let (_root, request) = fixture();
    let cwd = Path::new(&request.cwd);
    let home = Path::new(&request.home_dir);
    let settings = cwd.join("settings.sh");
    std::fs::write(&settings, "setting=ready").unwrap();
    std::os::unix::fs::symlink(&settings, cwd.join("settings-alias.sh")).unwrap();
    let first = cwd.join("first");
    let second = cwd.join("second");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    for (directory, mode, marker) in [(&first, 0o655, "first"), (&second, 0o755, "second")] {
        let path = directory.join("helper");
        std::fs::write(&path, format!("#!/bin/bash\nprintf {marker}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    let mut environment = environment(&request).unwrap();
    environment.insert(
        "PATH".into(),
        format!("{}:{}", first.display(), second.display()),
    );
    let resolver = Resolver {
        cwd,
        home,
        environment: &environment,
        names: &[],
        deadline: Instant::now() + Duration::from_secs(1),
        captured: RefCell::new(BTreeMap::new()),
        brokered_commands: RefCell::new(Vec::new()),
        source_snapshots: RefCell::new(BTreeMap::new()),
        source_contents: RefCell::new(BTreeMap::new()),
        network_destinations: RefCell::new(BTreeSet::new()),
    };
    let original = graph::Resolver::resolve_source(&resolver, "./settings.sh").unwrap();
    let alias = graph::Resolver::resolve_source(&resolver, "./settings-alias.sh").unwrap();
    assert!(Arc::ptr_eq(&original.source, &alias.source));
    let observed = std::process::Command::new("/bin/bash")
        .args(["--noprofile", "--norc", "-c", "helper"])
        .env_clear()
        .env("PATH", &environment["PATH"])
        .current_dir(cwd)
        .output()
        .unwrap();
    assert!(observed.status.success());
    let graph::Executable::Bash(helper) =
        graph::Resolver::resolve(&resolver, &["helper".into()]).unwrap()
    else {
        panic!("expected captured helper")
    };
    assert!(helper
        .source
        .contains(std::str::from_utf8(&observed.stdout).unwrap()));
}

#[test]
fn bash_resident_inspection_refuses_withheld_startup_and_function_values() {
    let (_root, mut request) = fixture();
    request
        .execution_environment
        .environment_names
        .push("BASH_ENV".into());
    assert_eq!(inspect(&request), Err("bash_startup_environment_unproven"));
    request.execution_environment.environment_names.pop();
    request.file_creation_mask = None;
    assert_eq!(
        inspect(&request),
        Err("native_bash_subject_creation_mask_unavailable")
    );
    request.file_creation_mask = Some(0o022);
    request
        .execution_environment
        .environment_names
        .push("LANG".into());
    assert_eq!(
        inspect(&request),
        Err("bash_host_environment_value_withheld")
    );
    request.execution_environment.environment_names.pop();
    request
        .execution_environment
        .environment_names
        .push("bash".into());
    // The invocation uses an absolute interpreter name, so this unrelated
    // variable cannot shadow it. A bare interpreter could be a Bash 3 function.
    request.command = request.command.replacen("/bin/bash", "bash", 1);
    assert_eq!(
        inspect(&request),
        Err("bash_command_environment_value_withheld")
    );
}

#[test]
fn bash_resident_inspection_rejects_sensitive_and_hardlinked_sources() {
    let (root, mut request) = fixture();
    let home = Path::new(&request.home_dir);
    std::fs::create_dir(home.join(".ssh")).unwrap();
    let sensitive = home.join(".ssh/id_rsa");
    std::fs::write(&sensitive, "printf synthetic").unwrap();
    request.command = format!("/bin/bash '{}'", sensitive.display());
    assert_eq!(inspect(&request), Err("bash_sensitive_code_path"));
    let alias = root.path().join("source-alias.sh");
    std::fs::hard_link(&sensitive, &alias).unwrap();
    request.command = format!("/bin/bash '{}'", alias.display());
    assert_eq!(inspect(&request), Err("bash_code_unreadable_or_oversized"));
}
