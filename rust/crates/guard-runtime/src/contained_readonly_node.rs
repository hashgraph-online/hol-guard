//! The environment a read-only Node run starts with.
//!
//! The caller's Node preloads and search paths are not repository input, so
//! they never reach the run. On Linux, Guard's own sink also asks the
//! planned runtime, under the same read-only sandbox, whether it takes
//! `--disable-wasm-trap-handler`, and sets that one option when it does:
//! WebAssembly's trap handler reserves a virtual cage larger than the run's
//! memory limits allow. The runtime's help is read only once the resident
//! allows it from every directory the run touches, and nothing in the
//! repository or the caller's `NODE_OPTIONS` is read as a capability.
//! This replays that step.

use super::*;

const WASM_TRAP_OPTION: &[u8] = b"--disable-wasm-trap-handler";
const PROBE_SECONDS: u64 = 10;

/// Settle `environment` for `plan`'s Node run, which `payload` asked for.
/// The help probe's private directory goes when the probe ends.
pub(super) fn settle(
    payload: &Map<String, Value>,
    workspace: &Path,
    authority: &Authority<'_>,
    plan: &ReadonlyPlan,
    environment: &mut BTreeMap<String, String>,
    signals: &process::Signals,
    timeout: u64,
) -> Outcome<()> {
    environment.remove("NODE_OPTIONS");
    environment.remove("NODE_PATH");
    if plan.backend != backend::BUBBLEWRAP {
        return Ok(());
    }
    let help = vec![plan.executable.clone(), "--help".to_owned()];
    let mut contexts = vec![path_text(workspace)?];
    if !contexts.contains(&plan.cwd) {
        contexts.push(plan.cwd.clone());
    }
    for directory in &contexts {
        let asked = with_command(payload, &help, Some(directory));
        let response = authority
            .authorize(&asked)
            .ok_or_else(Failure::unauthorized)?;
        if !allowed(&response) {
            return Err(Failure::unauthorized());
        }
    }
    let helper = ReadonlyPlan {
        profile_version: NODE_TEST_PROFILE.to_owned(),
        backend: plan.backend.clone(),
        backend_executable: plan.backend_executable.clone(),
        workspace: plan.workspace.clone(),
        cwd: plan.cwd.clone(),
        executable: plan.executable.clone(),
        command: help,
        allowed_executables: plan.allowed_executables.clone(),
        read_only_roots: Vec::new(),
        output_roots: Vec::new(),
        denied_capabilities: plan.denied_capabilities.clone(),
        user_site_root: None,
        settings: plan.settings.clone(),
    };
    let private = private_root()?;
    signals.clean_up(private.path.clone());
    let mut probe_environment = super::environment(&helper, &private)?;
    probe_environment.remove("NODE_OPTIONS");
    probe_environment.remove("NODE_PATH");
    let argv = process::launcher_argv(&backend::argv(&helper, &private)?)?;
    let captured = process::run_captured(
        &argv,
        &probe_environment,
        Path::new(&plan.cwd),
        &private.path,
        Duration::from_secs(timeout.min(PROBE_SECONDS)),
    )
    .filter(|captured| captured.code == 0)
    .ok_or_else(|| {
        Failure::new(
            "node_restricted_capabilities_unavailable",
            "Node runtime capability discovery did not finish.",
        )
    })?;
    if offers_wasm_trap_option(&captured.stdout) {
        environment.insert(
            "NODE_OPTIONS".to_owned(),
            String::from_utf8_lossy(WASM_TRAP_OPTION).into_owned(),
        );
    }
    Ok(())
}

/// Whether the resident allows the help outright.
fn allowed(response: &Map<String, Value>) -> bool {
    let text = |name: &str| response.get(name).and_then(Value::as_str);
    response.get("observe_mode") != Some(&Value::Bool(true))
        && text("decision") == Some("allow")
        && text("policy_action") == Some("allow")
}

/// Whether Node's help lists the option on a line of its own options: an
/// indented line that starts with it.
fn offers_wasm_trap_option(help: &[u8]) -> bool {
    help.split(|byte| *byte == b'\n').any(|line| {
        let indent = line
            .iter()
            .take_while(|byte| matches!(byte, b' ' | b'\t'))
            .count();
        indent > 0
            && line[indent..]
                .strip_prefix(WASM_TRAP_OPTION)
                .is_some_and(|rest| matches!(rest.first(), None | Some(b' ' | b'\t')))
    })
}

#[cfg(test)]
#[path = "contained_readonly_node_tests.rs"]
mod tests;
