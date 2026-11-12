use std::time::{Duration, Instant};

use guard_contracts::NativeCommandControlBindingV1;

use crate::native_command_controls::CompiledNativeCommandControls;
use crate::native_command_program::packaged_command_program;

const SECRET_READ: &str = "command.kubernetes-secrets.permission.secret-read";

fn controls(disabled: &[&str]) -> CompiledNativeCommandControls {
    let program = packaged_command_program().unwrap();
    let controls: Vec<_> = disabled
        .iter()
        .map(|permission| {
            serde_json::json!({
                "target_kind": "permission", "target_id": permission, "state": "disabled"
            })
        })
        .collect();
    let layers = if controls.is_empty() {
        serde_json::json!([])
    } else {
        serde_json::json!([{
            "schema_version": "1.0.0", "kind": "local-admin",
            "catalog_digest": program.catalog_digest, "global_lockdown": false,
            "controls": controls
        }])
    };
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest,
        "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest,
        "health": "protected", "revision": 1, "managed_revision": 0,
        "effective_digest": "", "layers": layers
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    CompiledNativeCommandControls::new(&binding).unwrap()
}

fn parse(command: &str) -> crate::CanonicalCommandV1 {
    crate::pretool::evaluate_pre_tool(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap()
    .command_model
}

fn timed_out(
    controls: &CompiledNativeCommandControls,
    command: &str,
) -> guard_contracts::PreToolResultV1 {
    let intrinsic = crate::pretool::evaluate_pre_tool_envelope(
        "claude-code",
        "PreToolUse",
        &serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}}),
    );
    controls.apply(
        &parse(command),
        intrinsic,
        Some(Instant::now() - Duration::from_secs(1)),
    )
}

#[test]
fn an_unrelated_disable_leaves_a_timed_out_check_reviewable() {
    // One disabled Kubernetes permission used to turn every slow check into
    // a block no approval could clear, `git diff --stat` included.
    let controls = controls(&[SECRET_READ]);
    for command in [
        "git diff --stat",
        "git log --oneline -5",
        "ls -la && pwd",
        "cargo test -q -p demo",
    ] {
        assert!(
            !controls.disabled_owner_in_reach(Some(&parse(command)), &[]),
            "{command}"
        );
        let result = timed_out(&controls, command);
        assert_eq!(result.minimum_action, "review", "{command}");
        assert_eq!(
            result.reason_code, "native_command_extension_evaluation_timed_out",
            "{command}"
        );
        assert_eq!(
            result.reason,
            crate::native_command_controls::floor::TIMED_OUT_REVIEW_REASON
        );
    }
}

#[test]
fn a_disable_the_command_could_reach_keeps_the_timeout_blocked() {
    let controls = controls(&[SECRET_READ]);
    for command in [
        "kubectl get secret db -o yaml",
        "oc get secrets",
        "git diff --stat && kubectl get secret db",
        "sh -c 'kubectl get secret db'",
        "bash deploy.sh",
        "./deploy.sh",
        "/usr/local/bin/kubectl get secret db",
        "timeout 5 kubectl get secret db",
        "env git diff",
        "$TOOL get secret db",
    ] {
        assert!(
            controls.disabled_owner_in_reach(Some(&parse(command)), &[]),
            "{command}"
        );
        let result = timed_out(&controls, command);
        assert_eq!(result.minimum_action, "block", "{command}");
    }
    // A tool call carries no shell text to bound, and package names go to
    // the delegated firewall this check does not model.
    assert!(controls.disabled_owner_in_reach(None, &[]));
    assert!(controls.disabled_owner_in_reach(Some(&parse("git diff")), &["left-pad".to_owned()]));
}

#[test]
fn nothing_disabled_is_never_in_reach() {
    let controls = controls(&[]);
    assert!(!controls.disabled_owner_in_reach(None, &[]));
    assert!(!controls.disabled_owner_in_reach(Some(&parse("kubectl get secret db")), &[]));
}
