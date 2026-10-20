//! The install-time config of the native bounded hook bridge: the argv
//! shapes an install writes, and the config fields the bridge reads after
//! every check `run_bounded_cli_hook` applies.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::bounded_hook_bridge_render::NATIVE_HARNESSES;
use crate::guard_store_json::py_repr_str;
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

pub(super) fn positive_seconds(value: Option<&PyVal>) -> Option<Duration> {
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
/// bridge does not port. A frozen config must say it is frozen, and one
/// without a `start_command` gets none: the command derived for an older
/// config starts a Python interpreter a frozen Guard has not got.
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
        None if frozen => Vec::new(),
        None => {
            let cli_args: Vec<&str> = cli_args.iter().filter_map(PyVal::as_str).collect();
            daemon_start_command(python_executable, package_root, guard_home, &cli_args)
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

/// `daemon_start_command(python_executable, package_root, guard_home,
/// cli_args)` (`bounded_cli_hook_native.py`) for an install whose config
/// predates `start_command`: the config already holds the resolved package
/// root and Guard home, and the canonical home is the `--home` argument,
/// else `Path.home()`.
pub(super) fn daemon_start_command(
    python_executable: &str,
    package_root: &str,
    guard_home: &str,
    cli_args: &[&str],
) -> Vec<String> {
    let home_dir = cli_args
        .windows(2)
        .find(|pair| pair[0] == "--home")
        .map(|pair| pair[1].to_owned())
        .or_else(python_home);
    let Some(home_dir) = home_dir else {
        return Vec::new();
    };
    let bootstrap = format!(
        "import os,sys;\
sys.path.insert(0, {});\
from pathlib import Path;\
from codex_plugin_scanner.guard.daemon import schedule_guard_daemon_recovery;\
failure_kind=os.environ.get('HOL_GUARD_HOOK_FAILURE_KIND','transport-failure');\
failure_kind=failure_kind if failure_kind in \
{{'overload','transport-failure','authenticated-control-plane-failure'}} \
else 'transport-failure';\
schedule_guard_daemon_recovery(Path({}),home_dir=Path({}),failure_kind=failure_kind)",
        py_repr_str(package_root),
        py_repr_str(guard_home),
        py_repr_str(&home_dir),
    );
    vec![
        python_executable.to_owned(),
        "-I".to_owned(),
        "-c".to_owned(),
        bootstrap,
    ]
}

/// `str(Path.home())`: `HOME` on POSIX, `USERPROFILE` on Windows.
fn python_home() -> Option<String> {
    let name = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var(name).ok().filter(|home| !home.is_empty())
}
