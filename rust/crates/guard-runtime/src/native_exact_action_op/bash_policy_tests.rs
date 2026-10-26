//! A captured benign helper cannot launder a disabled command permission.

use super::*;
use crate::policy_enforcement::{
    tests::{policy, snapshot},
    AdmittedPolicySnapshot,
};
use guard_contracts::NativeCommandControlBindingV1;
use serde_json::json;

#[test]
fn closed_bash_graph_can_run_without_consent_when_current_policy_allows_every_effect() {
    let (_root, request) = tests::fixture();
    let captured = capture_for_launch(&request, &tests::admitted("allow")).unwrap();
    let decisions = &captured.policy.as_ref().unwrap().decisions;
    assert!(
        decisions
            .iter()
            .all(|decision| decision.decision == "allow"),
        "{:?}",
        decisions
            .iter()
            .map(|decision| (&decision.minimum_action, &decision.reason_code))
            .collect::<Vec<_>>()
    );
}

pub(super) fn protected_controls() -> NativeCommandControlBindingV1 {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(json!({
        "schema":"guard.native-command-control-binding.v1",
        "program_digest":program.program_digest, "catalog_digest":program.catalog_digest,
        "trust_digest":program.trust_digest, "health":"protected", "revision":1,
        "managed_revision":0, "effective_digest":"", "layers":[]
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    binding
}

#[test]
fn closed_bash_quiet_proof_also_applies_with_authenticated_command_controls() {
    let (_root, request) = tests::fixture();
    let mut current = snapshot(policy("allow"));
    current.command_extensions = Some(protected_controls());
    let current = AdmittedPolicySnapshot::new(current).unwrap();
    let captured = capture_for_launch(&request, &tests::admitted("allow")).unwrap();
    let assessment = super::super::super::bash_policy::assess(
        &captured.graph,
        &request,
        &current,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    assert!(
        assessment.allows_without_consent(),
        "{:?}",
        assessment
            .decisions
            .iter()
            .map(|decision| (&decision.minimum_action, &decision.reason_code))
            .collect::<Vec<_>>()
    );
}

#[test]
fn captured_helper_cannot_discharge_a_specific_package_review() {
    let (_root, request) = tests::fixture();
    let cwd = Path::new(&request.cwd);
    std::fs::write(
        cwd.join("npm"),
        "#!/bin/bash\nprintf 'local fixture only\\n'\n",
    )
    .unwrap();
    std::fs::set_permissions(cwd.join("npm"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(cwd.join("maintenance.sh"), "npm run build\n").unwrap();
    let mut current = snapshot(policy("allow"));
    current.command_extensions = Some(protected_controls());
    let current = AdmittedPolicySnapshot::new(current).unwrap();
    match capture_for_launch(&request, &current) {
        Err(reason) => assert_eq!(reason, "bash_current_policy_denied"),
        Ok(captured) => {
            let assessment = captured.policy.as_ref().unwrap();
            assert!(!assessment.allows_without_consent());
            assert!(assessment
                .decisions
                .iter()
                .any(|decision| decision.reason_code == "native_package_review"));
        }
    }
}

#[test]
fn captured_report_never_targets_configured_guard_state_even_through_an_alias() {
    let (_root, request) = tests::fixture();
    let protected = Path::new(&request.guard_home).join("protected-state");
    std::fs::write(&protected, "protected Guard state").unwrap();
    let alias = Path::new(&request.cwd).join("state-alias");
    std::os::unix::fs::symlink(&request.guard_home, &alias).unwrap();
    for target in [protected.clone(), alias.join("protected-state")] {
        std::fs::write(
            Path::new(&request.cwd).join("maintenance.sh"),
            format!(": > '{}'\n", target.display()),
        )
        .unwrap();
        assert!(
            matches!(capture_for_launch(&request, &tests::admitted("allow")),
            Err(reason) if reason == "bash_output_guard_state_protected")
        );
        assert_eq!(
            std::fs::read_to_string(&protected).unwrap(),
            "protected Guard state"
        );
    }
}

#[test]
fn bash_nested_extension_deny_survives_allowed_parent_and_sibling() {
    let (_root, request) = tests::fixture();
    let cwd = Path::new(&request.cwd);
    let helper = cwd.join("aws");
    // This is a local fake helper. No network client or command is executed.
    std::fs::write(&helper, "#!/bin/bash\nprintf 'local fixture only\\n'\n").unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(
        cwd.join("maintenance.sh"),
        "aws s3 ls\nprintf 'allowed sibling\\n'\n",
    )
    .unwrap();
    let captured = capture_for_launch(&request, &tests::admitted("allow")).unwrap();
    let identity = captured.subject.identity_sha256().unwrap();

    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(json!({
        "schema":"guard.native-command-control-binding.v1",
        "program_digest":program.program_digest,
        "catalog_digest":program.catalog_digest,
        "trust_digest":program.trust_digest,
        "health":"protected", "revision":1, "managed_revision":0, "effective_digest":"",
        "layers":[{
            "schema_version":"1.0.0", "kind":"local-admin", "catalog_digest":program.catalog_digest,
            "global_lockdown":false,
            "controls":[{"target_kind":"permission","target_id":"command.storage.aws-s3.permission.ls","state":"disabled"}]
        }]
    })).unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let mut changed = snapshot(policy("allow"));
    changed.command_extensions = Some(binding);
    let changed = AdmittedPolicySnapshot::new(changed).unwrap();
    let assessment = super::super::super::bash_policy::assess(
        &captured.graph,
        &request,
        &changed,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    assert_ne!(assessment.decisions[0].minimum_action, "block");
    assert!(assessment
        .decisions
        .iter()
        .skip(1)
        .any(|decision| decision.minimum_action == "block"
            && decision.reason_code == "native_command_permission_disabled"));
    assert!(assessment.has_hard_deny());
    assert_eq!(
        inspect(&request).unwrap().identity_sha256().unwrap(),
        identity
    );
    assert!(
        matches!(capture_for_launch(&request, &changed), Err(reason) if reason == "bash_current_policy_denied")
    );
}
