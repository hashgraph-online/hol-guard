use super::CompiledNativeCommandControls;
use guard_contracts::{
    NativeCommandControlBindingV1, NativeExtensionControlLayerV1, NativeExtensionControlV1,
    NATIVE_COMMAND_CONTROL_BINDING_SCHEMA,
};
use std::fs;
use std::path::{Path, PathBuf};

/// Controls with the contributed `command.ollama` extension and every
/// permission it declares enabled, or with nothing enabled.
fn controls(enabled: bool) -> CompiledNativeCommandControls {
    let program = crate::native_command_program::authored_test_support::full_program();
    let ids: &[(&str, &str)] = if enabled {
        &[
            ("extension", "command.ollama"),
            ("permission", "command.ollama.permission.push"),
            ("permission", "command.ollama.permission.rm"),
        ]
    } else {
        &[]
    };
    let mut binding = NativeCommandControlBindingV1 {
        active_security_digest: None,
        schema: NATIVE_COMMAND_CONTROL_BINDING_SCHEMA.into(),
        authority: None,
        program_digest: program.program_digest.clone(),
        catalog_digest: program.catalog_digest.clone(),
        trust_digest: program.trust_digest.clone(),
        health: "protected".into(),
        revision: 1,
        managed_revision: 0,
        effective_digest: String::new(),
        layers: vec![NativeExtensionControlLayerV1 {
            schema_version: "1.0.0".into(),
            kind: "local-admin".into(),
            catalog_digest: program.catalog_digest.clone(),
            global_lockdown: false,
            controls: ids
                .iter()
                .map(|(kind, id)| NativeExtensionControlV1 {
                    target_kind: (*kind).into(),
                    target_id: (*id).into(),
                    state: "enabled".into(),
                })
                .collect(),
        }],
    };
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    CompiledNativeCommandControls::for_program(&binding, program).unwrap()
}

struct Fixture(PathBuf);

impl Fixture {
    /// A project holding an ordinary file, a secret, and a link to the secret.
    fn new() -> Self {
        // Under /tmp rather than the per-user temporary directory, which
        // Guard treats as an allowed location of its own.
        let root = PathBuf::from(format!(
            "/tmp/guard-contributed-allow-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        let project = root.join("home/project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("README.md"), "fixture\n").unwrap();
        fs::write(project.join(".env"), "SYNTHETIC_ONLY=fixture\n").unwrap();
        std::os::unix::fs::symlink(project.join(".env"), project.join("alias")).unwrap();
        Self(root.canonicalize().unwrap())
    }

    fn evaluate(&self, controls: &CompiledNativeCommandControls, command: &str) -> String {
        let home = self.0.join("home");
        let cwd: &Path = &home.join("project");
        crate::pretool::evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
            Some(controls),
            None,
            home.to_str(),
            cwd.to_str(),
        )
        .minimum_action
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A contributed extension's allowed action passes inside a compound when
/// every other step passes as a command of its own.
///
/// The reads after the allowed step used to lose their proof because an
/// earlier step was not proven safe by Guard itself, so the compound asked
/// although each of its steps passed alone.
#[test]
fn an_allowed_contributed_action_passes_with_reads_after_it() {
    let fixture = Fixture::new();
    let allowed = controls(true);
    for command in [
        "ollama rm stale-model",
        "ls -la",
        "cat README.md",
        "ollama rm stale-model && ls -la && cat README.md",
        "ollama rm stale-model && cat README.md",
        "ollama rm stale-model; ls -la",
    ] {
        assert_eq!(fixture.evaluate(&allowed, command), "allow", "{command}");
    }
}

/// A step that does not pass alone keeps the compound from passing, and the
/// action itself still needs the user's Allow.
#[test]
fn a_step_that_fails_alone_still_holds_the_compound() {
    let fixture = Fixture::new();
    let allowed = controls(true);
    for command in [
        "cat alias",
        "ollama rm stale-model && cat alias",
        "ollama rm stale-model && cat .env",
    ] {
        assert_ne!(fixture.evaluate(&allowed, command), "allow", "{command}");
    }
    let unset = controls(false);
    assert_ne!(
        fixture.evaluate(&unset, "ollama rm stale-model && ls -la && cat README.md"),
        "allow"
    );
}
