//! The launcher sources `durable_harness_launcher.py` rendered: the Python
//! shim that re-enters Guard through the trusted loader, the `/bin/sh` shim
//! that runs a durable `hol-guard`, and the Windows `.cmd` beside either.

use std::path::{Path, PathBuf};

use guard_command::shims::{parse_py_str_list, TRUSTED_CLI_LAUNCHER};

use super::kimi::expand_user;
use super::{desktop_core, path_text, which, Ctx};
use crate::guard_store_json::py_repr_str;
use crate::local_cli_identify::shlex_quote;

/// Path fragments of an ephemeral location (`_TRANSIENT_PATH_FRAGMENTS`).
const TRANSIENT_FRAGMENTS: [&str; 6] = [
    "/var/folders/",
    "/private/var/folders/",
    "/tmp/",
    "/private/tmp/",
    "/temp/",
    "pytest-of-",
];

/// The installing interpreter the Python launcher is built from.
pub(super) struct Interpreter {
    pub(super) executable: String,
    pub(super) frozen: bool,
    /// `package_shim_interpreter()`: the frozen CLI or the executable.
    pub(super) package_interpreter: String,
    pub(super) python_flags: Vec<String>,
    pub(super) import_root: String,
    /// `merge_guard_launcher_env()`, in order.
    pub(super) launcher_env: Vec<(String, String)>,
}

fn repr_list(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|item| py_repr_str(item)).collect();
    format!("[{}]", parts.join(", "))
}

fn repr_dict(items: &[(String, String)]) -> String {
    let parts: Vec<String> = items
        .iter()
        .map(|(key, value)| format!("{}: {}", py_repr_str(key), py_repr_str(value)))
        .collect();
    format!("{{{}}}", parts.join(", "))
}

/// `shims._is_transient_path`.
pub(super) fn is_transient(ctx: &Ctx, path: &Path) -> bool {
    let text = path_text(path);
    if TRANSIENT_FRAGMENTS
        .iter()
        .any(|fragment| text.contains(fragment))
    {
        return true;
    }
    let resolved = ctx.resolved(path);
    ["TMPDIR", "TEMP", "TMP"].iter().any(|name| {
        ctx.env(name)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some_and(|value| resolved.starts_with(ctx.resolved(&expand_user(ctx, value))))
    })
}

/// `is_transient_appimage_path`.
pub(super) fn is_appimage(ctx: &Ctx, value: &str) -> bool {
    let normalized = path_text(&ctx.absolute(&expand_user(ctx, value)))
        .replace('\\', "/")
        .to_lowercase();
    normalized.contains("/tmp/.mount_") || normalized.contains("/private/tmp/.mount_")
}

/// `durable_guard_cli_path`.
fn durable_cli(ctx: &Ctx, desktop: Option<&Path>, runtime: &str) -> Option<PathBuf> {
    let mut candidates: Vec<String> = Vec::new();
    candidates.extend(desktop.map(path_text));
    candidates.extend(
        ctx.env("HOL_GUARD_DESKTOP_RUNTIME_OWNER")
            .map(str::to_owned),
    );
    candidates.push(path_text(
        &ctx.home.join(".local").join("bin").join("hol-guard"),
    ));
    candidates.push(runtime.to_owned());
    for candidate in candidates.iter().filter(|candidate| !candidate.is_empty()) {
        let invocation = ctx.absolute(&expand_user(ctx, candidate));
        let Ok(resolved) = std::fs::canonicalize(&invocation) else {
            continue;
        };
        if let Some(shim) = desktop_core::shim_for_executable(ctx, &resolved) {
            let Ok(resolved_shim) = std::fs::canonicalize(ctx.absolute(&shim)) else {
                continue;
            };
            if shim.is_file()
                && which::executable(&shim)
                && !is_transient(ctx, &shim)
                && !is_transient(ctx, &resolved_shim)
            {
                return Some(shim);
            }
            continue;
        }
        if !invocation.is_file() || !which::executable(&invocation) {
            continue;
        }
        if is_transient(ctx, &invocation) || is_transient(ctx, &resolved) {
            continue;
        }
        return Some(invocation);
    }
    None
}

/// `build_durable_cli_shim`.
fn durable_shim(ctx: &Ctx, fixed: &[String], desktop: Option<&Path>, runtime: &str) -> String {
    let official = durable_cli(ctx, desktop, runtime);
    let quoted_args: Vec<String> = fixed.iter().map(|arg| shlex_quote(arg)).collect();
    let mut metadata = vec![official
        .as_deref()
        .map_or_else(|| "hol-guard".to_owned(), path_text)];
    metadata.extend(fixed.iter().cloned());
    let quoted_cli = official
        .as_deref()
        .map_or_else(|| "''".to_owned(), |path| shlex_quote(&path_text(path)));
    [
        "#!/bin/sh".to_owned(),
        format!("# base_command = {}", repr_list(&metadata)),
        format!("guard_cli={quoted_cli}"),
        "if [ ! -x \"$guard_cli\" ]; then".to_owned(),
        "        echo \"HOL Guard needs the durable official install. Run: pipx install --force hol-guard\" >&2".to_owned(),
        "        exit 127".to_owned(),
        "fi".to_owned(),
        "original_count=$#".to_owned(),
        "for arg do".to_owned(),
        "    set -- \"$@\" \"--arg=$arg\"".to_owned(),
        "done".to_owned(),
        "shift \"$original_count\"".to_owned(),
        format!("exec \"$guard_cli\" {} \"$@\"", quoted_args.join(" ")),
        String::new(),
    ]
    .join("\n")
}

/// `build_harness_shim`: `context_args` are the home and workspace flags.
pub(super) fn harness_shim(
    ctx: &Ctx,
    harness: &str,
    context_args: &[String],
    interpreter: &Interpreter,
) -> String {
    let guard_home = path_text(&ctx.guard_home);
    let desktop = desktop_core::durable_current(ctx, &ctx.home);
    let executable = interpreter.executable.as_str();
    if desktop.is_some() || interpreter.frozen || is_appimage(ctx, executable) {
        let mut fixed = vec![
            "run".to_owned(),
            harness.to_owned(),
            "--guard-home".to_owned(),
            guard_home,
        ];
        fixed.extend(context_args.iter().cloned());
        let runtime = desktop
            .as_deref()
            .map_or_else(|| executable.to_owned(), path_text);
        return durable_shim(ctx, &fixed, desktop.as_deref(), &runtime);
    }
    let mut command = vec![executable.to_owned()];
    command.extend(interpreter.python_flags.iter().cloned());
    command.extend(
        [
            "-c",
            TRUSTED_CLI_LAUNCHER,
            &interpreter.import_root,
            "codex_plugin_scanner.cli",
            "guard",
            "run",
            harness,
            "--guard-home",
            &guard_home,
        ]
        .map(str::to_owned),
    );
    command.extend(context_args.iter().cloned());
    let mut lines = vec![
        format!("#!{executable}"),
        "from __future__ import annotations".to_owned(),
        "import os".to_owned(),
        "import sys".to_owned(),
        format!("base_command = {}", repr_list(&command)),
        format!("base_env = {}", repr_dict(&interpreter.launcher_env)),
    ];
    lines.extend(PYTHON_TAIL.iter().map(|line| (*line).to_owned()));
    lines.join("\n")
}

/// The Python shim after its two generated assignments.
const PYTHON_TAIL: [&str; 17] = [
    "combined_env = {**os.environ, **base_env}",
    "if 'PYTHONPATH' in os.environ and 'PYTHONPATH' in base_env:",
    "    pythonpath_entries = []",
    "    os_pythonpath = os.environ['PYTHONPATH'].split(os.pathsep)",
    "    base_pythonpath = base_env['PYTHONPATH'].split(os.pathsep)",
    "    for entry in [*os_pythonpath, *base_pythonpath]:",
    "        normalized = entry.strip()",
    "        if normalized and normalized not in pythonpath_entries:",
    "            pythonpath_entries.append(normalized)",
    "    combined_env['PYTHONPATH'] = os.pathsep.join(pythonpath_entries)",
    "extra_args = [f\"--arg={arg}\" for arg in sys.argv[1:]]",
    "argv = [*base_command, *extra_args]",
    "if os.name == 'nt':",
    "    import subprocess",
    "    sys.exit(subprocess.run(argv, env=combined_env, check=False).returncode)",
    "os.execvpe(argv[0], argv, combined_env)",
    "",
];

/// `_cmd_quote_fixed_argument`.
fn cmd_quote(value: &str) -> String {
    let value = value.replace('%', "%%");
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for character in value.chars() {
        if character == '\\' {
            backslashes += 1;
            continue;
        }
        if character == '"' {
            out.push_str(&"\\".repeat(backslashes * 2 + 1));
        } else {
            out.push_str(&"\\".repeat(backslashes));
        }
        out.push(character);
        backslashes = 0;
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// `_generated_harness_command`: the durable shim's commented argv.
fn generated_command(posix_path: &Path, source: &str) -> Option<Vec<String>> {
    let name = posix_path.file_name()?.to_string_lossy();
    if !name.starts_with("guard-") {
        return None;
    }
    let line = source
        .lines()
        .find_map(|line| line.strip_prefix("# base_command = "))?;
    let command = parse_py_str_list(line)?;
    (command.len() >= 3 && command[1] == "run").then_some(command)
}

/// `build_windows_script(package_shim_interpreter(), posix_path, source=...)`.
pub(super) fn windows_script(
    ctx: &Ctx,
    interpreter: &str,
    posix_path: &Path,
    source: &str,
) -> String {
    if is_appimage(ctx, interpreter) {
        return [
            "@echo off",
            "echo HOL Guard needs a durable Windows install before this launcher can run. 1>&2",
            "exit /b 127",
            "",
        ]
        .join("\r\n");
    }
    if let Some(command) = generated_command(posix_path, source) {
        let mut argv = vec![command[0].clone(), "run-shim".to_owned()];
        argv.extend(command[3..].iter().cloned());
        argv.push(command[2].clone());
        argv.push("--".to_owned());
        let line: Vec<String> = argv.iter().map(|value| cmd_quote(value)).collect();
        return [
            "@echo off".to_owned(),
            "setlocal DisableDelayedExpansion".to_owned(),
            format!("{} %*", line.join(" ")),
            String::new(),
        ]
        .join("\r\n");
    }
    [
        "@echo off".to_owned(),
        format!("\"{interpreter}\" \"{}\" %*", path_text(posix_path)),
        "exit /b".to_owned(),
        String::new(),
    ]
    .join("\r\n")
}
