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
//! A Vitest run or a build starts a transform image under Vitest's route,
//! so that route admits the help too. This replays that step.

use std::process::{Command, Stdio};

use super::*;

const WASM_TRAP_OPTION: &[u8] = b"--disable-wasm-trap-handler";
const PROBE_SECONDS: u64 = 10;

/// Settle `environment` for `plan`'s Node run, which `payload` asked for.
/// The help probe's private directory goes when the probe ends.
pub(in super::super) fn settle(
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
        if !allowed(&response, transform(plan)) {
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
    let help = run_probe(
        &argv,
        &probe_environment,
        Path::new(&plan.cwd),
        &private.path,
        signals,
        timeout.min(PROBE_SECONDS),
    )
    .ok_or_else(|| {
        Failure::new(
            "node_restricted_capabilities_unavailable",
            "Node runtime capability discovery did not finish.",
        )
    })?;
    if offers_wasm_trap_option(&help) {
        environment.insert(
            "NODE_OPTIONS".to_owned(),
            String::from_utf8_lossy(WASM_TRAP_OPTION).into_owned(),
        );
    }
    Ok(())
}

/// What the help probe `argv` printed, when it exits cleanly in time. The
/// launcher starts it in a session of its own, which is tracked like the run
/// itself: an interrupt reaches its whole group, and the group is killed
/// when the time runs out and once the probe exits.
fn run_probe(
    argv: &[String],
    environment: &BTreeMap<String, String>,
    cwd: &Path,
    scratch: &Path,
    signals: &process::Signals,
    seconds: u64,
) -> Option<Vec<u8>> {
    let (program, arguments) = argv.split_first()?;
    let stdout = process::capture_file(scratch, "node-help").ok()?;
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .envs(environment)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(stdout.try_clone().ok()?)
        .stderr(Stdio::null());
    let (status, timed_out) = process::run_tracked(&mut command, signals, seconds, true).ok()?;
    (!timed_out && status.map(process::exit_code) == Some(0)).then(|| process::read_all(stdout))
}

/// Whether `plan` starts a transform image, as a Vitest run and a build do.
fn transform(plan: &ReadonlyPlan) -> bool {
    matches!(
        plan.profile_version.as_str(),
        VITEST_PROFILE | NODE_BUILD_PROFILE
    )
}

/// Whether the resident allows the help outright or, for a run that starts
/// a transform image, reads it as a capability of a read-only Vitest run.
fn allowed(response: &Map<String, Value>, transform: bool) -> bool {
    let text = |name: &str| response.get(name).and_then(Value::as_str);
    response.get("observe_mode") != Some(&Value::Bool(true))
        && ((text("decision") == Some("allow") && text("policy_action") == Some("allow"))
            || (transform && readonly_route(response) == Some(VITEST_ROUTE)))
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
