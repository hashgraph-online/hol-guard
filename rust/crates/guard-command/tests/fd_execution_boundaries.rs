//! Search-result subprocesses require their own native execution proof.

use guard_command::native_command_controls::CompiledNativeCommandControls;
use guard_command::native_command_program::packaged_command_program;
use guard_command::pretool::evaluate_pre_tool_envelope_with_extensions;
use guard_command::{parse_command, CommandModelRequestV1};
use guard_contracts::NativeCommandControlBindingV1;
use serde_json::json;

fn request(command: &str) -> CommandModelRequestV1 {
    CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }
}

#[test]
fn fd_subprocess_searches_fail_closed_without_partial_command_evidence() {
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest,
        "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest,
        "health": "protected", "revision": 1, "managed_revision": 0,
        "effective_digest": "", "layers": [{
            "schema_version": "1.0.0", "catalog_digest": program.catalog_digest,
            "kind": "local-admin", "global_lockdown": false, "controls": [{
                "target_kind": "permission",
                "target_id": "command.filesystem.permission.recursive-delete",
                "state": "enabled"
            }]
        }]
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let controls = CompiledNativeCommandControls::new(&binding).unwrap();
    for command in [
        "fd -a SKILL.md ~/.codex/skills -d 1 -x sed -i '1,180p' {}",
        "fd -a SKILL.md ~/.codex/skills -d 1 -x 'sed;rm' -n '1,180p' {}",
        "fd -a SKILL.md ~/.codex/skills -d 1 -xsh -c 'echo blocked' {}",
        "fd -a SKILL.md ~/.codex/skills -d 1 -Hx sh -c 'echo blocked' {}",
        "fd SKILL.md -x sed -n '1,20p' {}",
        "fd -a SKILL.md ~/.codex/skills/ssh-link -d 1 -x sed -n '1,20p' {}",
        "fd -L id_rsa src -x sed -n '1,20p' {}",
        "fd --search-path ~/.ssh SKILL.md -x sed -n '1,20p' {}",
        "fd -a SKILL.md ~/.codex/skills/known-docs -d 1 -x sed -n '1,20p' {}",
        "fd -X rm {}",
        "fd --exec rm {}",
        "fd --exec=rm {}",
        "fd --exec-batch rm {}",
        "fd --exec-batch=rm {}",
        "fd -HXrm {}",
        "fd -tx --exec rm {}",
        "fd --exclude=-x SKILL.md -x rm {}",
        "fd -t d build -x rm -r {}",
        "fd -- -x src && fd SKILL.md -x rm {}",
        "fd.exe -x rm {}",
        "/usr/bin/fd -x rm {}",
        "sudo -n fd -x rm {}",
    ] {
        let model = parse_command(&request(command)).unwrap();
        assert_eq!(model.confidence, "uncertain", "{command}");
        assert_eq!(
            model.uncertainty_reason.as_deref(),
            Some("nested_command_executor_not_yet_supported"),
            "{command}"
        );
        assert!(model.segments.is_empty(), "{command}");

        let result = evaluate_pre_tool_envelope_with_extensions(
            "codex",
            "PreToolUse",
            &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
            Some(&controls),
            None,
        );
        assert_eq!(result.minimum_action, "block", "{command}");
        assert_eq!(result.decision, "deny", "{command}");
        assert!(!result.explicitly_benign, "{command}");
        let evidence = result.command_extensions.unwrap();
        assert!(evidence.observations.is_empty(), "{command}");
        assert!(evidence.permission_observations.is_empty(), "{command}");
        assert_eq!(evidence.binding.observation_count, 0, "{command}");
        assert_eq!(evidence.binding.uncertainty_count, 1, "{command}");
        assert_eq!(
            evidence.evaluation_error.as_deref(),
            Some("native_command_evaluation_failed"),
            "{command}"
        );
    }
}

#[test]
fn fd_literals_and_option_values_are_not_subprocess_requests() {
    for command in [
        "fd SKILL.md ~/.codex/skills",
        "fd -tx SKILL.md ~/.codex/skills",
        "fd -Ht x SKILL.md src",
        "fd --type executable SKILL.md src",
        "fd -- -x src",
        "fd -- --exec src",
        "fd --exclude -x SKILL.md src",
        "fd -E -x SKILL.md src",
        "fd -HEx SKILL.md src",
        "fd --exclude=--exec SKILL.md src",
        "fd --extension x SKILL.md src",
        "fd --path-separator -x SKILL.md src",
        "fd --search-path -x SKILL.md",
        "fd -c never SKILL.md src",
        "fd -cnever SKILL.md src",
        "printf '%s' 'fd -x rm {}'",
    ] {
        let model = parse_command(&request(command)).unwrap();
        assert_eq!(model.confidence, "exact", "{command}");
        assert!(model.uncertainty_reason.is_none(), "{command}");
        assert!(!model.segments.is_empty(), "{command}");
    }
}
