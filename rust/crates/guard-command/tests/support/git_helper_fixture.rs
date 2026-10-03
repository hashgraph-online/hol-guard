use serde_json::json;

pub struct FixtureCleanup(pub std::path::PathBuf);

impl Drop for FixtureCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// Cargo injects dynamic-loader settings into the test process. Model the
// synthetic hook caller explicitly rather than inheriting the build harness.
pub fn evaluate_pre_tool_envelope_with_context(
    harness: &str,
    event: &str,
    payload: &serde_json::Value,
    controls: Option<&guard_command::native_command_controls::CompiledNativeCommandControls>,
    deadline: Option<std::time::Instant>,
    home: Option<&str>,
    cwd: Option<&str>,
) -> guard_contracts::PreToolResultV1 {
    use sha2::{Digest, Sha256};
    let path = std::env::var("PATH").unwrap();
    let mut environment = std::collections::BTreeMap::from([
        ("PATH", path.clone()),
        ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
    ]);
    if let Some(home) = home {
        environment.insert("HOME", home.to_owned());
    }
    let context = guard_contracts::GuardExecutionEnvironmentV1 {
        path,
        environment_names: environment.keys().map(|key| (*key).to_owned()).collect(),
        environment_digest: hex::encode(Sha256::digest(serde_json::to_vec(&environment).unwrap())),
        home: home.map(str::to_owned),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
    };
    guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        harness,
        event,
        payload,
        controls,
        deadline,
        guard_command::pretool::PathContext {
            home_dir: home,
            cwd,
        },
        Some(&context),
    )
}

pub fn github_controls(
    state: &str,
) -> guard_command::native_command_controls::CompiledNativeCommandControls {
    git_github_controls(state, state)
}

pub fn git_github_controls(
    git_state: &str,
    github_state: &str,
) -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let mut value = json!({
        "schema":"guard.native-command-control-binding.v1",
        "program_digest":program.program_digest, "catalog_digest":program.catalog_digest,
        "trust_digest":program.trust_digest, "health":"protected", "revision":1,
        "managed_revision":0, "effective_digest":"", "layers":[{
            "schema_version":"1.0.0", "kind":"local-admin", "catalog_digest":program.catalog_digest,
            "global_lockdown":false, "controls":[
                {"target_kind":"permission", "target_id":"command.git.permission.status", "state":git_state},
                {"target_kind":"permission", "target_id":"command.git.permission.diff", "state":git_state},
                {"target_kind":"permission", "target_id":"command.git.permission.log", "state":git_state},
                {"target_kind":"permission", "target_id":"command.git.permission.show", "state":git_state},
                {"target_kind":"permission", "target_id":"command.github.permission.read-local", "state":github_state},
                {"target_kind":"permission", "target_id":"command.github.permission.read-remote", "state":github_state}
            ]
        }]
    });
    value["layers"][0]["controls"]
        .as_array_mut()
        .unwrap()
        .retain(|control| control["state"] != "default");
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(value).unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    guard_command::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap()
}
