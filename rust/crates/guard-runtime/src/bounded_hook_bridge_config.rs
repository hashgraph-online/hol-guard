//! The install-time config of the native bounded hook bridge: the argv
//! shapes an install writes, and the config fields the bridge reads after
//! every check `run_bounded_cli_hook` applies.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::{emit, fail, prepare, read_hook_input, Input, DEFAULT_EVENT};

use crate::bounded_hook_bridge_render::NATIVE_HARNESSES;
use crate::claude_hook_bridge::home_directory;
use crate::claude_hook_bridge_recovery::frozen_recovery_command;
use crate::hook_process_spawn::isolated_daemon_start_command;
use crate::pyjson::{self, PyVal};

pub(super) const MANAGED_MARKER: &str = "HOL_GUARD_MANAGED_ZCODE";
/// The frozen Guard subcommand an install names in place of `-I -c <bootstrap>`.
const FROZEN_COMMAND: &str = "__guard-bounded-hook";

/// The fields of the install-time config the native bridge reads, after
/// every check `run_bounded_cli_hook` applies.
#[derive(Debug, PartialEq)]
pub(crate) struct BridgeConfig {
    pub(crate) harness: String,
    pub(crate) guard_home: PathBuf,
    pub(crate) timeout: Duration,
    /// The daemon-start command, empty when the install wrote none.
    pub(crate) start_command: Vec<String>,
}

/// The config argument of `[python, "-I", "-c", bootstrap, config]`, or of
/// a frozen Guard's `[guard, "__guard-bounded-hook", config]`, with ZCode's
/// trailing `# HOL_GUARD_MANAGED_ZCODE` when a shell kept it.
pub(crate) fn config_argument(python_argv: &[String]) -> Option<&str> {
    let (index, marked) = match python_argv {
        [_, isolated, code, _, _] if isolated == "-I" && code == "-c" => (4, None),
        [_, isolated, code, _, _, hash, marker] if isolated == "-I" && code == "-c" => {
            (4, Some((hash, marker)))
        }
        [_, command, _] if command == FROZEN_COMMAND => (2, None),
        [_, command, _, hash, marker] if command == FROZEN_COMMAND => (2, Some((hash, marker))),
        _ => return None,
    };
    let marked_ok = marked.is_none_or(|(hash, marker)| hash == "#" && marker == MANAGED_MARKER);
    marked_ok.then(|| python_argv[index].as_str())
}

/// Whether `python_argv` names a frozen Guard rather than an interpreter.
pub(super) fn frozen_launch(python_argv: &[String]) -> bool {
    python_argv
        .get(1)
        .is_some_and(|command| command == FROZEN_COMMAND)
}

pub(crate) fn positive_seconds(value: Option<&PyVal>) -> Option<Duration> {
    let seconds = match value? {
        PyVal::Int(digits) => digits.parse::<f64>().ok()?,
        PyVal::Float(number) => *number,
        _ => return None,
    };
    if !seconds.is_finite() || seconds <= 0.0 {
        return None;
    }
    Duration::try_from_secs_f64(seconds).ok()
}

/// The config a POSIX install wrote for the launcher its argv named, or
/// `None` for anything Python would refuse or handle in a step the native
/// bridge does not port. A frozen config must say it is frozen. A config
/// without a `start_command` gets the one its launcher would have written:
/// the interpreter's isolated recovery bootstrap, or the frozen Guard's
/// private recovery argument.
pub(crate) fn parse_launch_config(argument: &str, frozen: bool) -> Option<BridgeConfig> {
    let parsed = pyjson::parse_mapping_lone_surrogates(argument).ok()?;
    if parsed.mapped {
        return None;
    }
    let payload = parsed.value;
    payload.as_dict()?;
    let python_executable = payload.get("python_executable")?.as_str()?;
    let package_root = payload.get("package_root")?.as_str()?;
    let guard_home = payload.get("guard_home")?.as_str()?;
    let cli_args = payload.get("cli_args")?.as_list()?;
    let harness = payload.get("harness")?.as_str()?;
    let timeout = positive_seconds(payload.get("timeout_seconds"))?;
    let start_command = match payload.get("start_command") {
        None => {
            let cli_args: Vec<&str> = cli_args.iter().filter_map(PyVal::as_str).collect();
            daemon_start_command(
                python_executable,
                package_root,
                guard_home,
                &cli_args,
                frozen,
            )
        }
        Some(value) => value
            .as_list()?
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()?,
    };
    let launcher_ok = match payload.get("frozen_launcher") {
        None | Some(PyVal::Bool(false)) => !frozen,
        Some(PyVal::Bool(true)) => frozen,
        Some(_) => false,
    };
    if !launcher_ok
        || !cli_args.iter().all(|item| item.as_str().is_some())
        || !NATIVE_HARNESSES.contains(&harness)
        || !Path::new(guard_home).is_absolute()
    {
        return None;
    }
    Some(BridgeConfig {
        harness: harness.to_owned(),
        guard_home: PathBuf::from(guard_home),
        timeout,
        start_command,
    })
}

/// The daemon-start command an install derives from its launcher
/// (`daemon_start_command` or `frozen_daemon_start_command`,
/// `bounded_cli_hook_native.py`): the canonical home is the `--home`
/// argument, else `Path.home()`. Empty when there is no home to name.
pub(super) fn daemon_start_command(
    python_executable: &str,
    package_root: &str,
    guard_home: &str,
    cli_args: &[&str],
    frozen: bool,
) -> Vec<String> {
    let named_home = cli_args
        .windows(2)
        .find(|pair| pair[0] == "--home")
        .map(|pair| PathBuf::from(pair[1]));
    let guard_home = Path::new(guard_home);
    if frozen {
        let Some(home_dir) = named_home.or_else(home_directory) else {
            return Vec::new();
        };
        return frozen_recovery_command(python_executable, guard_home, &home_dir)
            .unwrap_or_default();
    }
    isolated_daemon_start_command(
        python_executable,
        Path::new(package_root),
        guard_home,
        named_home.as_deref(),
    )
}

/// `main_from_argv` for a config the native bridge does not serve: the
/// `_emit_failure` answer Python gives a config it refuses. Python fails
/// one without a usable timeout before reading the hook, and any other
/// for the event the hook names. No install writes such a config for the
/// native bridge, so the hook fails closed rather than running Python.
pub(super) fn refuse_config(argument: Option<&str>, started: Instant) -> i32 {
    let payload = argument
        .and_then(|text| pyjson::parse_mapping_lone_surrogates(text).ok())
        .map(|parsed| parsed.value)
        .filter(|value| value.as_dict().is_some());
    let harness = payload
        .as_ref()
        .and_then(|value| value.get("harness")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned());
    let deadline = payload
        .as_ref()
        .and_then(|value| positive_seconds(value.get("timeout_seconds")))
        .and_then(|timeout| started.checked_add(timeout));
    let Some(deadline) = deadline else {
        return fail(&harness, DEFAULT_EVENT, false);
    };
    let Input::Read(raw) = read_hook_input(deadline) else {
        return fail(&harness, DEFAULT_EVENT, false);
    };
    let route = match prepare(&raw) {
        Ok(prepared) => prepared.failed(),
        Err(refused) => refused,
    };
    emit(&harness, route)
}
