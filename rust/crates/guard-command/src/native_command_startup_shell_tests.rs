//! A shell under options Guard cannot read keeps its block, and the reason
//! names those options and the plain `bash -c` spelling Guard does review.

use super::STARTUP_SHELL_REASON;
use crate::native_command_controls::CompiledNativeCommandControls;
use crate::native_command_program::packaged_command_program;
use guard_contracts::NativeCommandControlBindingV1;

fn evaluate(command: &str) -> guard_contracts::PreToolResultV1 {
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest, "health": "protected",
        "revision": 1, "managed_revision": 0, "effective_digest": "", "layers": []
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let controls = CompiledNativeCommandControls::new(&binding).unwrap();
    crate::pretool::evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &serde_json::json!({"tool_name":"bash","tool_input":{"command":command}}),
        Some(&controls),
        None,
        Some("/home/tester"),
        Some("/home/tester/project"),
    )
}

#[test]
fn a_startup_shell_block_names_the_options_and_the_reviewed_spelling() {
    for command in [
        "bash -lc 'ls'",
        "zsh -c 'git status'",
        "bash --posix -c 'ls'",
    ] {
        let result = evaluate(command);
        assert_eq!(result.minimum_action, "block", "{command}");
        assert_eq!(result.reason, STARTUP_SHELL_REASON, "{command}");
    }
}

#[test]
fn a_shell_plain_dash_c_cannot_read_keeps_its_own_reason() {
    let result = evaluate("bash -lc 'echo $HOME'");
    assert_ne!(result.reason, STARTUP_SHELL_REASON);
}
