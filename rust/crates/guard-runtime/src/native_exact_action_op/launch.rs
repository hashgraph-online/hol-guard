//! Launch-identity proofs for exact-action approvals.
//!
//! A launch identity binds the code a reviewed command would run. Anything
//! that loads code the identity cannot bind (interpreters, task runners,
//! wrappers) is refused with a stable once-only reason unless its module graph
//! is content-bound (`node <script>`), and a compound command
//! is persistable only when every segment passes the same proof.

use std::path::Path;

use guard_command::command_model::{parse_shell_command, CanonicalCommand, CommandSegment};
use guard_command::secret_path_probe::is_request_secret_path;
use serde_json::{json, Value};

use super::context::Ctx;
use super::fs_path;
#[cfg(not(windows))]
use super::git_identity::git_readonly_identity;
#[cfg(windows)]
use super::launch_windows;
use super::launcher_sets::{is_destructive, is_python_launcher, loads_unbound_code};
#[cfg(not(windows))]
use super::node_script::node_script;
use super::node_script::NODE_LAUNCHERS;
use super::operands::{argument_value, file_operand_hashes};
#[cfg(not(windows))]
use super::python_script::python_script;
#[cfg(windows)]
use super::reasons::GIT_HELPER_CONFIG;
use super::reasons::{
    Proof, COMPOUND_COMMAND, DESTRUCTIVE_COMMAND, MUTABLE_LAUNCHER, SENSITIVE_PATH, UNPROVEN_LAUNCH,
};
#[cfg(not(windows))]
use super::runner_bin::runner_local_bin;
use super::runner_bin::LOCAL_BIN_RUNNERS;

const MAX_COMPOUND_SEGMENTS: usize = 8;

/// The launch identity of a shell command a harness tool runs.
///
/// On Windows only a POSIX shell is modeled: Claude Code runs `Bash` in Git
/// Bash and the Pi family runs `bash`. PowerShell (Codex, any `PowerShell`
/// tool) parses, aliases and profiles commands in ways the POSIX parser does
/// not see, so its launches stay once-only.
pub(super) fn shell_launch_identity(
    harness: &str,
    tool_name: &str,
    command: &str,
    cwd: &str,
    ctx: &Ctx,
) -> Proof<Value> {
    #[cfg(windows)]
    if !launch_windows::runs_posix_shell(harness, tool_name) {
        return Err(UNPROVEN_LAUNCH);
    }
    let _ = (harness, tool_name);
    launch_identity(command, cwd, ctx)
}

/// The launch identity of a command, or the once-only reason it has none.
///
/// On Windows a segment is persistable only when it starts a native image
/// (`launch_windows`) or runs a read-only git from a Git for Windows install;
/// interpreters, runners and batch files stay once-only because their proofs
/// bind POSIX layouts (`bin/`, `site-packages`, shell shims).
pub(super) fn launch_identity(command: &str, cwd: &str, ctx: &Ctx) -> Proof<Value> {
    if command.trim().is_empty() {
        return Err(UNPROVEN_LAUNCH);
    }
    ctx.check()?;
    let model = parse_shell_command(
        command,
        Some(Path::new(cwd)),
        ctx.home.map(Path::new),
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    if model.segments.len() > 1 {
        return compound_identity(&model, cwd, ctx);
    }
    if !is_safe_single_invocation(&model) {
        return Err(UNPROVEN_LAUNCH);
    }
    let segment = &model.segments[0];
    segment_launch(
        segment,
        &normalized_name(segment.executable.as_deref()),
        command,
        cwd,
        ctx,
        false,
    )
}

/// A single top-level invocation without wrappers, environment prefixes or redirects.
fn is_safe_single_invocation(model: &CanonicalCommand) -> bool {
    let simple_model = model.confidence == "exact"
        && model.redirects.is_empty()
        && model.embedded_commands.is_empty()
        && !model.path_overridden()
        && model.wrapper_chain.is_empty()
        && model.segments.len() == 1;
    simple_model && {
        let segment = &model.segments[0];
        segment.execution_context == "top:0"
            && segment.pipeline_index == 0
            && segment.environment_names.is_empty()
            && segment.wrapper_chain.is_empty()
            && !segment.path_overridden
            && segment.executable.is_some()
    }
}

/// Bind every segment of `a && b` / `a; b` / `a | b` to its own proof.
fn compound_identity(model: &CanonicalCommand, cwd: &str, ctx: &Ctx) -> Proof<Value> {
    if model.confidence != "exact"
        || !model.redirects.is_empty()
        || !model.embedded_commands.is_empty()
        || !model.wrapper_chain.is_empty()
        || model.path_overridden()
        || model.segments.len() > MAX_COMPOUND_SEGMENTS
    {
        return Err(COMPOUND_COMMAND);
    }
    let mut segments: Vec<Value> = Vec::new();
    let mut segment_cwd = cwd.to_owned();
    for segment in &model.segments {
        ctx.check()?;
        let executable = segment.executable.as_deref().unwrap_or("");
        if !segment.execution_context.starts_with("top:")
            || !segment.environment_names.is_empty()
            || !segment.wrapper_chain.is_empty()
            || segment.path_overridden
            || executable.is_empty()
        {
            return Err(COMPOUND_COMMAND);
        }
        let name = normalized_name(Some(executable));
        if name == "cd" {
            segment_cwd = cd_target(&segment.arguments, &segment_cwd)?;
            segments.push(json!({"kind": "cd", "target": segment_cwd}));
            continue;
        }
        match segment_launch(segment, &name, "", &segment_cwd, ctx, true) {
            Ok(launch) => segments.push(launch),
            Err(UNPROVEN_LAUNCH | MUTABLE_LAUNCHER) => return Err(COMPOUND_COMMAND),
            Err(other) => return Err(other),
        }
    }
    Ok(json!({"kind": "compound", "segments": segments}))
}

fn cd_target(arguments: &[String], cwd: &str) -> Proof<String> {
    if arguments.len() != 1 || arguments[0].starts_with(['-', '$', '~']) {
        return Err(COMPOUND_COMMAND);
    }
    let resolved =
        fs_path::resolve_strict(&fs_path::join(cwd, &arguments[0])).ok_or(COMPOUND_COMMAND)?;
    if fs_path::is_dir(&resolved) {
        Ok(resolved)
    } else {
        Err(COMPOUND_COMMAND)
    }
}

/// `executable_name(...)` lowercased, with `.exe` then `.cmd` removed; on
/// Windows every extension `CreateProcessW` or `cmd.exe` starts is removed.
fn normalized_name(executable: Option<&str>) -> String {
    let base = executable.unwrap_or("").replace('\\', "/");
    let mut name = base.rsplit('/').next().unwrap_or("").to_lowercase();
    let suffixes: &[&str] = if cfg!(windows) {
        &[".exe", ".com", ".bat", ".cmd"]
    } else {
        &[".exe", ".cmd"]
    };
    for suffix in suffixes {
        if let Some(stripped) = name.strip_suffix(suffix) {
            name = stripped.to_owned();
        }
    }
    name
}

fn argument_is_sensitive(argument: &str, cwd: &str, home: Option<&str>) -> bool {
    let value = argument_value(argument);
    !value.is_empty()
        && !value.starts_with('-')
        && is_request_secret_path(value, Some(Path::new(cwd)), home.map(Path::new))
}

fn segment_launch(
    segment: &CommandSegment,
    name: &str,
    command: &str,
    cwd: &str,
    ctx: &Ctx,
    compound: bool,
) -> Proof<Value> {
    let arguments = &segment.arguments;
    if is_destructive(name) {
        return Err(DESTRUCTIVE_COMMAND);
    }
    if arguments
        .iter()
        .any(|argument| argument_is_sensitive(argument, cwd, ctx.home))
    {
        return Err(SENSITIVE_PATH);
    }
    let operands = file_operand_hashes(arguments, cwd, ctx).ok_or(UNPROVEN_LAUNCH)?;
    platform_segment(segment, name, command, cwd, ctx, compound, operands)
}

#[cfg(not(windows))]
fn platform_segment(
    segment: &CommandSegment,
    name: &str,
    command: &str,
    cwd: &str,
    ctx: &Ctx,
    compound: bool,
    operands: Vec<Value>,
) -> Proof<Value> {
    let arguments = &segment.arguments;
    let executable = segment.executable.as_deref().unwrap_or("");
    let reusable_identity = || -> Proof<Value> {
        let identity = ctx
            .engines
            .launch_identity(executable, arguments, cwd, ctx.home, ctx.env);
        if ctx.engines.launch_reusable(&identity) {
            Ok(identity)
        } else {
            Err(UNPROVEN_LAUNCH)
        }
    };
    if name == "git" {
        let binary = reusable_identity()?;
        let git = git_readonly_identity(arguments, cwd, &[ctx.engines.system_git_config()], ctx)?;
        return Ok(json!({"kind": "direct", "identity": binary, "git": git, "operands": operands}));
    }
    if LOCAL_BIN_RUNNERS.contains(&name) {
        let local_bin = if compound {
            None
        } else {
            runner_local_bin(command, name, arguments, cwd, ctx, true)
        };
        let local_bin = local_bin.ok_or(MUTABLE_LAUNCHER)?;
        return Ok(
            json!({"kind": "runner-local-bin", "runner": name, "local_bin": local_bin, "operands": operands}),
        );
    }
    if NODE_LAUNCHERS.contains(&name) && !compound {
        let script = node_script(arguments, cwd, ctx)?;
        return Ok(
            json!({"kind": "node-script", "identity": reusable_identity()?, "script": script, "operands": operands}),
        );
    }
    if is_python_launcher(name) && !compound {
        let identity = reusable_identity()?;
        let script = python_script(arguments, cwd, ctx, &identity["executable"])?;
        return Ok(
            json!({"kind": "python-script", "identity": identity, "script": script, "operands": operands}),
        );
    }
    if loads_unbound_code(name, arguments) {
        return Err(MUTABLE_LAUNCHER);
    }
    Ok(json!({"kind": "direct", "identity": reusable_identity()?, "operands": operands}))
}

/// A Windows segment: a native image that loads no code it names elsewhere.
///
/// Git reads repository config, attributes, hooks and PATH helpers that no
/// digest binds on Windows, so a git launch, by spelling or by bound image,
/// always stays once-only there.
#[cfg(windows)]
fn platform_segment(
    segment: &CommandSegment,
    name: &str,
    _command: &str,
    cwd: &str,
    ctx: &Ctx,
    _compound: bool,
    operands: Vec<Value>,
) -> Proof<Value> {
    let arguments = &segment.arguments;
    let executable = segment.executable.as_deref().unwrap_or("");
    let launches_code = |name: &str| {
        LOCAL_BIN_RUNNERS.contains(&name)
            || NODE_LAUNCHERS.contains(&name)
            || is_python_launcher(name)
            || loads_unbound_code(name, arguments)
    };
    if is_git(name) {
        return Err(GIT_HELPER_CONFIG);
    }
    if launches_code(name) {
        return Err(MUTABLE_LAUNCHER);
    }
    let identity = ctx
        .engines
        .launch_identity(executable, arguments, cwd, ctx.home, ctx.env);
    let identity = launch_windows::native_launch(identity, executable, cwd, ctx)?;
    // The bound image's own name is checked as well as the spelled one.
    let stem = launch_windows::image_stem(&identity);
    if is_git(&stem) {
        return Err(GIT_HELPER_CONFIG);
    }
    if is_destructive(&stem) {
        return Err(DESTRUCTIVE_COMMAND);
    }
    if launches_code(stem.as_str()) {
        return Err(MUTABLE_LAUNCHER);
    }
    Ok(json!({"kind": "direct", "identity": identity, "operands": operands}))
}

/// Git and the Git for Windows programs that run it on the repository
/// (`git-*` helpers, `gitk`, `scalar`).
#[cfg(windows)]
fn is_git(name: &str) -> bool {
    name == "git" || name.starts_with("git-") || matches!(name, "gitk" | "scalar")
}
