use serde_json::json;

pub struct FixtureCleanup(pub std::path::PathBuf);

impl Drop for FixtureCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The canonical path as an agent would spell it. On Windows,
/// `std::fs::canonicalize` returns the `\\?\` extended-length form, which no
/// harness sends, in which `/` is not a separator and which Git for Windows
/// cannot create directories under; tests resolve links and 8.3 short names
/// but drop that prefix.
pub fn canonical_spelling(path: impl AsRef<std::path::Path>) -> std::path::PathBuf {
    let canonical = std::fs::canonicalize(path).unwrap();
    let Some(text) = canonical.to_str() else {
        return canonical;
    };
    if let Some(share) = text.strip_prefix(r"\\?\UNC\") {
        return std::path::PathBuf::from(format!(r"\\{share}"));
    }
    text.strip_prefix(r"\\?\")
        .map_or(canonical.clone(), std::path::PathBuf::from)
}

/// A path as an unquoted shell word. Git Bash strips unquoted backslashes,
/// so Guard never takes a backslash spelling as proof of a path; Windows
/// agents write the forward-slash form instead.
pub fn shell_word(path: &std::path::Path) -> String {
    let text = path.to_str().unwrap();
    if cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text.to_owned()
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
    evaluate_with_shell_home(harness, event, payload, controls, deadline, home, cwd, true)
}

/// As [`evaluate_pre_tool_envelope_with_context`], with the shell's HOME
/// either `home` or, when it should not match, the working directory.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_with_shell_home(
    harness: &str,
    event: &str,
    payload: &serde_json::Value,
    controls: Option<&guard_command::native_command_controls::CompiledNativeCommandControls>,
    deadline: Option<std::time::Instant>,
    home: Option<&str>,
    cwd: Option<&str>,
    shell_home_matches: bool,
) -> guard_contracts::PreToolResultV1 {
    let path = std::env::var("PATH").unwrap();
    evaluate_on_path(
        (harness, event),
        payload,
        (controls, deadline),
        (home, cwd, shell_home_matches),
        path,
    )
}

/// As [`evaluate_pre_tool_envelope_with_context`], for a shell whose `PATH`
/// finds a Node the workspace sandbox may run, wherever the host keeps its own.
/// Hosted CI runners keep Node in a world-writable directory the sandbox
/// refuses to execute from, so a command that runs it would otherwise stay at
/// review for the host instead of running contained.
#[cfg(unix)]
pub fn evaluate_with_node(
    harness: &str,
    event: &str,
    payload: &serde_json::Value,
    controls: Option<&guard_command::native_command_controls::CompiledNativeCommandControls>,
    home: &std::path::Path,
    cwd: Option<&str>,
) -> guard_contracts::PreToolResultV1 {
    let bin = stand_ins(
        home,
        ".nvm/versions/node/v25.2.1/bin",
        &["node", "npm", "npx"],
    );
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    evaluate_on_path(
        (harness, event),
        payload,
        (controls, None),
        (home.to_str(), cwd, true),
        path,
    )
}

/// As [`evaluate_with_node`], with a Python the workspace sandbox may run as
/// well. Hosted runners keep Python in a tool cache the sandbox refuses to
/// execute from, just as they do Node.
#[cfg(unix)]
pub fn evaluate_with_node_and_python(
    harness: &str,
    event: &str,
    payload: &serde_json::Value,
    controls: Option<&guard_command::native_command_controls::CompiledNativeCommandControls>,
    home: &std::path::Path,
    cwd: Option<&str>,
) -> guard_contracts::PreToolResultV1 {
    let node = stand_ins(
        home,
        ".nvm/versions/node/v25.2.1/bin",
        &["node", "npm", "npx"],
    );
    let python = stand_ins(home, ".pyenv/versions/3.12.8/bin", &["python3"]);
    let path = format!(
        "{}:{}:{}",
        node.display(),
        python.display(),
        std::env::var("PATH").unwrap()
    );
    evaluate_on_path(
        (harness, event),
        payload,
        (controls, None),
        (home.to_str(), cwd, true),
        path,
    )
}

/// Writes runnable stand-ins for `names` into `home`/`dir` and returns that
/// directory.
#[cfg(unix)]
fn stand_ins(home: &std::path::Path, dir: &str, names: &[&str]) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin = home.join(dir);
    std::fs::create_dir_all(&bin).unwrap();
    for name in names {
        let tool = bin.join(name);
        std::fs::write(&tool, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    bin
}

pub fn evaluate_on_path(
    (harness, event): (&str, &str),
    payload: &serde_json::Value,
    (controls, deadline): (
        Option<&guard_command::native_command_controls::CompiledNativeCommandControls>,
        Option<std::time::Instant>,
    ),
    (home, cwd, shell_home_matches): (Option<&str>, Option<&str>, bool),
    path: String,
) -> guard_contracts::PreToolResultV1 {
    use sha2::{Digest, Sha256};
    let mut environment = std::collections::BTreeMap::from([
        ("PATH", path.clone()),
        ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
    ]);
    // A mismatched shell stamps the working directory as its HOME.
    let shell_home = if shell_home_matches { home } else { cwd };
    if let Some(home) = shell_home {
        environment.insert("HOME", home.to_owned());
    }
    let context = guard_contracts::GuardExecutionEnvironmentV1 {
        path,
        environment_names: environment.keys().map(|key| (*key).to_owned()).collect(),
        environment_digest: hex::encode(Sha256::digest(serde_json::to_vec(&environment).unwrap())),
        home: shell_home.map(str::to_owned),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        ..Default::default()
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
            cdpath_unset: false,
            rustup_override_absent: false,
            cargo_config_inert: false,
            npm_config_inert: false,
            pip_config_inert: false,
            shell_home_matches: false,
            ripgrep_config_absent: false,
            gem_config_absent: false,
            http_config_absent: false,
            openssl_config_absent: false,
            psql_environment: Default::default(),
            creates_nothing: false,
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
    let controls = [
        ("command.git.permission.status", git_state),
        ("command.git.permission.diff", git_state),
        ("command.git.permission.log", git_state),
        ("command.git.permission.show", git_state),
        ("command.github.permission.read-local", github_state),
        ("command.github.permission.read-remote", github_state),
    ]
    .into_iter()
    .filter(|(_, state)| *state != "default")
    .map(|(target, state)| json!({"target_kind":"permission", "target_id":target, "state":state}))
    .collect();
    local_admin_controls(controls)
}

/// Every permission in the packaged catalog enabled, as the Extensions page
/// writes it when the user allows each of an extension's patterns.
pub fn every_permission_enabled(
) -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let controls = program
        .extensions
        .iter()
        .flat_map(|extension| extension.permissions.iter())
        .map(|permission| {
            json!({"target_kind":"permission", "target_id":permission.permission_id, "state":"enabled"})
        })
        .collect();
    local_admin_controls(controls)
}

/// A control binding carrying `controls` in one local-admin layer, signed
/// against the packaged command program the runtime under test loads.
pub fn local_admin_controls(
    controls: Vec<serde_json::Value>,
) -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let value = json!({
        "schema":"guard.native-command-control-binding.v1",
        "program_digest":program.program_digest, "catalog_digest":program.catalog_digest,
        "trust_digest":program.trust_digest, "health":"protected", "revision":1,
        "managed_revision":0, "effective_digest":"", "layers":[{
            "schema_version":"1.0.0", "kind":"local-admin", "catalog_digest":program.catalog_digest,
            "global_lockdown":false, "controls":controls
        }]
    });
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(value).unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    guard_command::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap()
}

/// Runs `git` in `directory` with `home` as HOME, with the repository
/// variables Cargo or an outer checkout may have exported removed, so the
/// fixture's own configuration is the only one Git reads.
pub fn git(home: &std::path::Path, directory: &std::path::Path, arguments: &[&str]) {
    let mut command = std::process::Command::new("git");
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_NAMESPACE",
    ] {
        command.env_remove(name);
    }
    let status = command
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}
