//! Whether a command line is the exact native Grok hook launch Guard writes,
//! which `cli/grok_hook_validation.py` decided before it moved here.
//!
//! A command is parsed into its argv, never run: `[runtime, "bounded-hook-bridge",
//! config]` (also behind an older `python -I` client), or the ten-element signed
//! Desktop proxy script. The bridge config must name the Grok harness, this
//! caller's interpreter and package, and a Guard hook invocation whose paths
//! are absolute and, when an owner is given, are that owner's.

use std::path::{Path, PathBuf};

use super::{caller, proxy_launch, Ctx};
use crate::bounded_hook_bridge::{BRIDGE_COMMAND, BRIDGE_FEATURE};
use crate::cloud_request_text::py_strip;
use crate::native_install_verdict::Runner;
use crate::pyjson::{self, PyVal};

/// The Guard store, home and workspace a hook must belong to.
pub(super) struct Owner<'a> {
    pub(super) guard_home: &'a Path,
    pub(super) home: &'a Path,
    pub(super) workspace: Option<&'a Path>,
}

/// A bridge config that passed every check, with the values callers compare.
struct Config {
    guard_home: String,
    package_root: String,
    cli_args: Vec<String>,
}

impl Config {
    fn options(&self) -> Vec<(&str, &str)> {
        let end = self.cli_args.len() - 1;
        self.cli_args[2..end]
            .chunks(2)
            .map(|pair| (pair[0].as_str(), pair[1].as_str()))
            .collect()
    }
}

/// An orphaned client's script (when it names one) and the home it serves.
struct Binding {
    script: Option<PathBuf>,
    home: PathBuf,
}

/// The facts one validation reads: the caller's process and whether Desktop
/// signing can be verified here.
pub(super) struct Checker<'a, R: Runner> {
    ctx: &'a Ctx,
    macos: bool,
    runner: &'a mut R,
}

fn arguments(command: &str) -> Vec<String> {
    let parsed = if cfg!(windows) {
        guard_runtime_windows_process::command_line_to_argv(command)
    } else {
        crate::daemon_lifecycle_text::shlex_split(command)
    };
    let args = parsed.unwrap_or_default();
    // Rebuilding the line also rejects shell expansions and operators that
    // sit outside quoted arguments.
    if !args.is_empty()
        && crate::harness_shell_command::platform_command_line(&args) == py_strip(command)
    {
        args
    } else {
        Vec::new()
    }
}

fn is_native_launch(args: &[String]) -> bool {
    args.len() == 3 && args[1] == BRIDGE_COMMAND
}

/// `python`, `python3`, `python3.11`, `python.exe`: an old client's interpreter.
fn is_python_name(path: &str) -> bool {
    let Some(name) = Path::new(path).file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("python") else {
        return false;
    };
    let version = rest.strip_suffix(".exe").unwrap_or(rest);
    version.is_empty()
        || version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

impl<'a, R: Runner> Checker<'a, R> {
    pub(super) fn new(ctx: &'a Ctx, macos: bool, runner: &'a mut R) -> Self {
        Self { ctx, macos, runner }
    }

    fn same_path(&self, left: &str, right: &Path) -> bool {
        self.ctx.resolved(Path::new(left)) == self.ctx.resolved(right)
    }

    /// Split a native runtime launch into its own argv. `trusted` also
    /// requires the runtime to be this host's validated one.
    fn native_client(
        &self,
        args: Vec<String>,
        trusted: bool,
        guard_home: Option<&Path>,
    ) -> Option<Vec<String>> {
        if args.len() < 2 || args[1] != BRIDGE_COMMAND {
            return Some(args);
        }
        if !matches!(args.len(), 3 | 6)
            || (args.len() == 6 && args[3] != "-I")
            || !Path::new(&args[0]).is_absolute()
        {
            return None;
        }
        if trusted {
            let runtime = proxy_launch::bridge(self.ctx, BRIDGE_FEATURE, guard_home).ok()??;
            if !self.same_path(&args[0], Path::new(&runtime)) {
                return None;
            }
        }
        Some(if args.len() == 3 {
            args
        } else {
            args[2..].to_vec()
        })
    }

    fn matches_owner(&self, options: &[(&str, &str)], owner: &Owner<'_>) -> bool {
        let option = |name: &str| {
            options
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| *value)
        };
        let Some(guard_home) = option("--guard-home") else {
            return false;
        };
        let user_home = self.ctx.user_home.to_string_lossy().into_owned();
        let home = option("--home").unwrap_or(&user_home);
        if !self.same_path(guard_home, owner.guard_home) || !self.same_path(home, owner.home) {
            return false;
        }
        match (owner.workspace, option("--workspace")) {
            (None, workspace) => workspace.is_none(),
            (Some(expected), Some(workspace)) => self.same_path(workspace, expected),
            (Some(_), None) => false,
        }
    }

    /// Bind the bridge configuration to its executable and Grok hook invocation.
    fn config(
        &self,
        text: &str,
        executable: &str,
        frozen: bool,
        owner: Option<&Owner<'_>>,
    ) -> Option<Config> {
        let config = pyjson::parse(text).ok()?;
        let string = |key: &str| config.get(key).and_then(PyVal::as_str);
        if string("harness") != Some("grok")
            || !matches!(config.get("frozen_launcher"), Some(PyVal::Bool(flag)) if *flag == frozen)
            || string("python_executable") != Some(executable)
        {
            return None;
        }
        let timeout = match config.get("timeout_seconds") {
            Some(PyVal::Int(digits)) => digits
                .parse::<i128>()
                .is_ok_and(|seconds| 0 < seconds && seconds <= 120),
            Some(PyVal::Float(seconds)) => *seconds > 0.0 && *seconds <= 120.0,
            _ => false,
        };
        let guard_home = string("guard_home").filter(|path| Path::new(path).is_absolute())?;
        let package_root = string("package_root").filter(|path| Path::new(path).is_absolute())?;
        let cli_args = config
            .get("cli_args")?
            .as_list()?
            .iter()
            .map(|arg| arg.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()?;
        if !timeout
            || cli_args.len() < 3
            || (cli_args.len() - 3) % 2 != 0
            || cli_args[..2] != ["guard", "hook"]
            || cli_args.last().map(String::as_str) != Some("--json")
        {
            return None;
        }
        let checked = Config {
            guard_home: guard_home.to_owned(),
            package_root: package_root.to_owned(),
            cli_args,
        };
        let options = checked.options();
        let keys: Vec<&str> = options.iter().map(|(key, _)| *key).collect();
        if (0..keys.len()).any(|index| keys[..index].contains(&keys[index])) {
            return None;
        }
        let option = |name: &str| options.iter().find(|(key, _)| *key == name);
        if option("--harness").map(|(_, value)| *value) != Some("grok")
            || !keys.iter().all(|key| {
                matches!(
                    *key,
                    "--harness" | "--guard-home" | "--home" | "--workspace"
                )
            })
        {
            return None;
        }
        let configured = option("--guard-home").map(|(_, value)| *value)?;
        if configured.is_empty() || !self.same_path(configured, Path::new(guard_home)) {
            return None;
        }
        if options
            .iter()
            .any(|(key, value)| *key != "--harness" && !Path::new(value).is_absolute())
        {
            return None;
        }
        if let Some(owner) = owner {
            if !self.matches_owner(&options, owner) {
                return None;
            }
        }
        Some(checked)
    }

    /// Only the generated macOS script over verified same-team app paths.
    fn desktop_proxy(&mut self, args: &[String], owner: Option<&Owner<'_>>) -> Option<Config> {
        let (config, core) =
            crate::desktop_hook_proxy::verified_launch(args, self.macos, self.runner)?;
        self.config(&config, &core, true, owner)
    }

    /// Reject marker-only commands without executing untrusted hook text.
    pub(super) fn recognizes(&mut self, command: &str, owner: Option<&Owner<'_>>) -> bool {
        let guard_home = owner.map(|owner| owner.guard_home);
        let Some(args) = self.native_client(arguments(command), true, guard_home) else {
            return false;
        };
        if args.len() == 10 {
            return self.desktop_proxy(&args, owner).is_some();
        }
        if !is_native_launch(&args) {
            return false;
        }
        let (Ok(frozen), Ok(executable), Ok(package_root)) = (
            caller::frozen(self.ctx),
            caller::cli_executable(self.ctx),
            caller::package_root(self.ctx),
        ) else {
            return false;
        };
        // The config names the package this process imports from, unless the
        // process is a frozen build with none.
        self.config(&args[2], executable, frozen, owner)
            .is_some_and(|config| frozen || config.package_root == package_root)
    }

    fn binding(&mut self, text: &str, old_client: bool) -> Option<Binding> {
        let args = self.native_client(arguments(text), false, None)?;
        if args.is_empty() || !Path::new(&args[0]).is_absolute() {
            return None;
        }
        let (script, serialized) = if args.len() == 4 && args[1] == "-I" {
            // Migration must work even when the old interpreter is gone.
            if !is_python_name(&args[0]) {
                return None;
            }
            (Some(PathBuf::from(&args[2])), args[3].clone())
        } else if old_client {
            return None;
        } else if is_native_launch(&args) {
            (None, args[2].clone())
        } else if args.len() == 10 && self.desktop_proxy(&args, None).is_some() {
            (None, args[7].clone())
        } else {
            return None;
        };
        let raw = pyjson::parse(&serialized).ok()?;
        raw.as_dict()?;
        let frozen = match raw.get("frozen_launcher") {
            Some(PyVal::Bool(flag)) => *flag,
            _ => return None,
        };
        let executable = raw
            .get("python_executable")
            .and_then(PyVal::as_str)
            .filter(|path| Path::new(path).is_absolute())?;
        let config = self.config(&serialized, executable, frozen, None)?;
        let expected = Path::new(&config.guard_home)
            .join("managed")
            .join("bounded-hooks")
            .join("grok.py");
        if let Some(script) = &script {
            if !script.is_absolute() || *script != expected {
                return None;
            }
        }
        // Workspace is a fallback for hosts without cwd, not an ownership
        // boundary: these commands all live in the same global Grok config.
        let user_home = self.ctx.user_home.to_string_lossy().into_owned();
        let home = config
            .options()
            .iter()
            .find(|(key, _)| *key == "--home")
            .map_or(user_home, |(_, value)| (*value).to_owned());
        Some(Binding {
            script,
            home: self.ctx.resolved(Path::new(&home)),
        })
    }

    /// An orphaned generated client for the same user home. Migration
    /// recognition only, never proof that a hook is operational.
    pub(super) fn is_missing(&mut self, command: &str, replacement: &str) -> bool {
        let (Some(old), Some(new)) = (
            self.binding(command, true),
            self.binding(replacement, false),
        ) else {
            return false;
        };
        old.script
            .is_some_and(|script| old.home == new.home && !self.ctx.absolute(&script).exists())
    }
}

#[cfg(all(test, unix))]
#[path = "tests_grok_hook_command.rs"]
mod tests;
