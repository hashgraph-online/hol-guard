//! Generation of the package-shim source and the Windows launcher.

use super::template::{Dyn, Line, TEMPLATE, TRUSTED_CLI_LAUNCHER};
use super::values::{py_float_repr, py_repr_list};
use super::{ShimContext, ShimFacts, ShimResult};
use crate::hook_adapter_pytext::py_repr_str;

/// `package_shim_interpreter()`.
pub(crate) fn package_shim_interpreter(facts: &ShimFacts) -> String {
    if facts.frozen {
        facts.frozen_cli.clone()
    } else {
        facts.executable.clone()
    }
}

/// `package_shim_needs_shell_wrapper()`.
pub(crate) fn needs_shell_wrapper(facts: &ShimFacts) -> bool {
    facts.frozen || facts.executable.contains(' ')
}

/// `_trusted_python_flags()`.
pub(crate) fn trusted_python_flags(facts: &ShimFacts) -> Vec<String> {
    let mut flags = vec!["-I".to_owned()];
    if facts.python_version >= (3, 11) {
        flags.push("-P".to_owned());
    }
    flags
}

/// `_package_protect_command_args`.
pub(crate) fn package_protect_command_args(context: &ShimContext) -> Vec<String> {
    let facts = &context.facts;
    let mut protect_args = vec![
        "protect".to_owned(),
        "--package-shim-ui".to_owned(),
        "--guard-home".to_owned(),
        context.guard_home.clone(),
    ];
    if let Some(home) = &context.home_dir {
        protect_args.push("--home".to_owned());
        protect_args.push(home.clone());
    }
    if facts.frozen {
        let mut command = vec![package_shim_interpreter(facts)];
        command.extend(protect_args);
        return command;
    }
    let mut command = vec![facts.executable.clone()];
    command.extend(trusted_python_flags(facts));
    command.extend([
        "-c".to_owned(),
        TRUSTED_CLI_LAUNCHER.to_owned(),
        facts.import_root.clone(),
        "codex_plugin_scanner.cli".to_owned(),
        "guard".to_owned(),
    ]);
    command.extend(protect_args);
    command
}

/// `_build_package_manager_python_shim`.
pub(crate) fn build_package_manager_python_shim(
    context: &ShimContext,
    command: &str,
) -> ShimResult<String> {
    let facts = &context.facts;
    let resolved_shim_dir = facts.resolve(&context.shim_dir())?;
    let base_command = package_protect_command_args(context);
    let mut lines: Vec<String> = Vec::with_capacity(TEMPLATE.len());
    for line in TEMPLATE {
        lines.push(match line {
            Line::Static(text) => text.to_owned(),
            Line::Dynamic(Dyn::Interpreter) => format!("#!{}", package_shim_interpreter(facts)),
            Line::Dynamic(Dyn::BaseCommand) => {
                format!("base_command = {}", py_repr_list(&base_command))
            }
            Line::Dynamic(Dyn::CommandName) => format!("command_name = {}", py_repr_str(command)),
            Line::Dynamic(Dyn::ImportRoot) => {
                format!("guard_cli_cwd = {}", py_repr_str(&facts.import_root))
            }
            Line::Dynamic(Dyn::GuardHome) => {
                format!("guard_home = {}", py_repr_str(&context.guard_home))
            }
            Line::Dynamic(Dyn::ShimDir) => {
                format!("shim_dir = {}", py_repr_str(&resolved_shim_dir))
            }
            Line::Dynamic(Dyn::SqliteTimeout) => format!(
                "store_lock_retry_timeout_seconds = {}",
                py_float_repr(facts.sqlite_connect_timeout_seconds)
            ),
        });
    }
    Ok(lines.join("\n"))
}

/// `is_transient_appimage_path`.
pub(crate) fn is_transient_appimage_path(facts: &ShimFacts, value: &str) -> ShimResult<bool> {
    let expanded = facts.expanduser(value)?;
    let normalized = facts.absolute(&expanded).replace('\\', "/").to_lowercase();
    Ok(normalized.contains("/tmp/.mount_") || normalized.contains("/private/tmp/.mount_"))
}

/// `_build_windows_script(posix_path)` for a package shim.
pub(crate) fn build_windows_script(facts: &ShimFacts, posix_path: &str) -> ShimResult<String> {
    let interpreter = package_shim_interpreter(facts);
    if is_transient_appimage_path(facts, &interpreter)? {
        return Ok([
            "@echo off",
            "echo HOL Guard needs a durable Windows install before this launcher can run. 1>&2",
            "exit /b 127",
            "",
        ]
        .join("\r\n"));
    }
    Ok([
        "@echo off".to_owned(),
        format!("\"{interpreter}\" \"{posix_path}\" %*"),
        String::new(),
    ]
    .join("\r\n"))
}

/// The launcher paths a shim install writes for `command`.
pub(crate) fn launcher_paths(facts: &ShimFacts, shim_dir: &str, command: &str) -> (String, String) {
    (
        facts.join(shim_dir, command),
        facts.join(shim_dir, &format!("{command}.cmd")),
    )
}
