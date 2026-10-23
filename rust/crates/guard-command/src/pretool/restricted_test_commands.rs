//! Pre-tool screens for the commands that run a project's tests and
//! formatters: pytest, `unittest`, test-named Python, Node, Bun and tsx
//! scripts, Prettier checks and the package-manager scripts that wrap them.
//! Each screen decides whether the command stays inside an already-admitted
//! containment boundary, so the file is runtime policy, not a test module.

use crate::CanonicalCommandV1;

#[path = "bun_eval_screen.rs"]
mod bun_eval_screen;
#[path = "package_script_route.rs"]
pub(super) mod package_script;

/// Bun evaluation shares the Node evaluation profile under its own reason, so
/// a receipt can admit Bun's package-protection permission without admitting
/// it for `node -e`.
const BUN_EVAL_REASON: &str = "native_bun_eval_readonly_containment_required";

fn python_runtime_name(name: &str) -> bool {
    // Windows resolves `python3` to `python.exe`, case-insensitively.
    let lowered;
    let name = if cfg!(windows) {
        lowered = name.to_ascii_lowercase();
        lowered.strip_suffix(".exe").unwrap_or(&lowered)
    } else {
        name
    };
    name.strip_prefix("python").is_some_and(|suffix| {
        suffix.is_empty()
            || suffix
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

/// Strip capability-reducing isolation flags; anything else ends the prefix.
fn python_after_isolation_flags(arguments: &[String]) -> Option<&[String]> {
    let mut rest = arguments;
    let mut flags = 0_u8;
    while let Some(flag) = rest.first() {
        let bits = match flag.as_str() {
            "-I" => 1,
            "-S" => 2,
            "-IS" | "-SI" => 3,
            _ => break,
        };
        if flags & bits != 0 {
            return None;
        }
        flags |= bits;
        rest = &rest[1..];
    }
    Some(rest)
}

fn python_inline_eval_args(arguments: &[String]) -> bool {
    python_after_isolation_flags(arguments)
        .is_some_and(|rest| matches!(rest, [flag, _program] if flag == "-c"))
}

/// `python3 test_calc.py`: a test-named workspace script. Run read-only it is
/// no more capable than inline evaluation of the same file, so it shares that
/// boundary. Other scripts usually write, so they stay reviewed.
fn python_test_script_args(arguments: &[String]) -> bool {
    python_after_isolation_flags(arguments).is_some_and(|rest| {
        matches!(rest, [script, ..] if workspace_relative(script) && test_script_name(script))
    })
}

/// `python3 -m unittest`: imports workspace test modules, which read-only is
/// no more capable than inline evaluation, so it shares that boundary.
fn python_unittest_args(arguments: &[String]) -> bool {
    python_after_isolation_flags(arguments).is_some_and(|rest| {
        matches!(rest, [flag, module, ..] if flag == "-m" && module == "unittest")
            && rest[2..]
                .iter()
                .all(|argument| !argument.contains(['<', '>', '|', '&', ';', '`', '$']))
    })
}

fn test_script_name(script: &str) -> bool {
    let name = script.rsplit('/').next().unwrap_or(script);
    let Some(stem) = name.strip_suffix(".py") else {
        return false;
    };
    stem.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        && (stem.starts_with("test_")
            || stem.ends_with("_test")
            || matches!(stem, "test" | "tests" | "runtests" | "run_tests"))
}

/// `math.test.ts`, `api.spec.mjs`, `test_calc.js`: the usual JavaScript and
/// TypeScript test file names.
fn node_test_script_name(script: &str) -> bool {
    let name = script.rsplit('/').next().unwrap_or(script);
    let Some((stem, extension)) = name.rsplit_once('.') else {
        return false;
    };
    matches!(
        extension,
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "mts" | "cts" | "tsx"
    ) && stem
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && (stem.ends_with(".test")
            || stem.ends_with(".spec")
            || stem.starts_with("test_")
            || stem.ends_with("_test")
            || matches!(stem, "test" | "tests"))
}

/// Type stripping and warning filters change how Node loads and reports a
/// script, not what the script can reach.
fn node_after_script_flags(arguments: &[String]) -> &[String] {
    let mut rest = arguments;
    while let [flag, tail @ ..] = rest {
        let neutral = matches!(
            flag.as_str(),
            "--experimental-strip-types" | "--experimental-transform-types" | "--no-warnings"
        ) || flag.strip_prefix("--disable-warning=").is_some_and(|code| {
            !code.is_empty()
                && code.len() <= 64
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        });
        if !neutral {
            break;
        }
        rest = tail;
    }
    rest
}

/// `node --experimental-strip-types math.test.ts`: a test-named workspace
/// script shares the inline evaluation boundary, as Python test scripts do.
fn node_test_script_args(arguments: &[String]) -> bool {
    matches!(node_after_script_flags(arguments), [script, ..]
        if workspace_relative(script) && node_test_script_name(script))
}

/// `tsx math.test.ts` in its installed forms. The sink loads the file through
/// the package's own loader inside the Vitest transform boundary.
fn tsx_test_script_args(name: &str, arguments: &[String]) -> bool {
    let rest = match (name, arguments) {
        ("tsx", rest) => rest,
        ("npx", [flag, tool, rest @ ..]) if flag == "--no-install" && tool == "tsx" => rest,
        ("npx", [tool, rest @ ..]) if tool == "tsx" => rest,
        ("node" | "nodejs", [entry, rest @ ..])
            if entry
                .replace('\\', "/")
                .ends_with("/node_modules/tsx/dist/cli.mjs") =>
        {
            rest
        }
        // The sink's own launch form, which the hook authorizes again before
        // running it. Typed directly, the sink does not prepare it.
        ("node" | "nodejs", [flag, loader, rest @ ..])
            if flag == "--import"
                && loader
                    .replace('\\', "/")
                    .ends_with("/node_modules/tsx/dist/loader.mjs") =>
        {
            rest
        }
        _ => return false,
    };
    matches!(rest, [script, ..] if workspace_relative(script) && node_test_script_name(script))
}

/// Classify a direct pytest invocation for delegation, never direct allowance.
/// The execution sink must resolve the interpreter and enforce pytest-readonly-v2.
pub(super) fn requires_pytest_containment(model: &CanonicalCommandV1) -> bool {
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || model.segments.len() != 1
    {
        return false;
    }
    let segment = &model.segments[0];
    if !segment.environment_names.is_empty() || segment.pipeline_index != 0 {
        return false;
    }
    let Some(executable) = segment.executable.as_deref() else {
        return false;
    };
    match super::executable_basename(executable) {
        "pytest" | "py.test" => true,
        "python" | "python3" => {
            matches!(segment.arguments.as_slice(), [module, target, ..] if module == "-m" && target == "pytest")
        }
        _ => false,
    }
}

/// The entrypoints Prettier publishes: version 3 moved the executable into
/// `bin/`, and version 2 is still installed widely enough to name as well.
pub(crate) const PRETTIER_ENTRIES: [&str; 2] =
    ["prettier/bin/prettier.cjs", "prettier/bin-prettier.js"];

/// Whether a Prettier command asks only whether the files are formatted.
/// `--check` and `--list-different` print and exit; every other spelling may
/// reach `--write`, which rewrites each file it visits.
pub(crate) fn prettier_checks(arguments: &[String]) -> bool {
    arguments.iter().any(|argument| {
        matches!(
            argument.as_str(),
            "--check" | "-c" | "--list-different" | "-l"
        )
    })
}

fn executable_is_bunx(executable: &str) -> bool {
    super::executable_basename(executable) == "bunx"
}

/// A lexical subdirectory; the sink resolves it and rejects escapes.
fn workspace_relative(directory: &str) -> bool {
    !directory.is_empty()
        && !directory.starts_with(['-', '/', '~', '$'])
        && !directory.contains(['\\', '$', '`'])
        && directory
            .trim_end_matches('/')
            .split('/')
            .all(|part| !part.is_empty() && part != "..")
}

fn bun_eval_flag(flag: &str) -> bool {
    matches!(flag, "-e" | "--eval" | "-p" | "--print")
}

/// Whether `reason` may carry the Node package-protection permission. Bun is a
/// package manager image, so its inline evaluation always reports it; the
/// evaluation still runs in the Node read-only boundary.
pub(super) fn package_permission_contained(
    reason: Option<&str>,
    model: Option<&CanonicalCommandV1>,
) -> bool {
    match reason {
        Some(
            "native_vitest_readonly_containment_required"
            | "native_package_test_readonly_containment_required"
            | "native_node_tool_readonly_containment_required"
            | "native_node_build_output_containment_required",
        ) => true,
        Some(BUN_EVAL_REASON) => model.is_some_and(bun_inline_eval),
        _ => false,
    }
}

/// `bun -e <program>` whose program passes the read-only screen. Anything
/// else keeps Bun's package-protection review.
fn bun_eval_args(arguments: &[String]) -> bool {
    matches!(arguments, [flag, program]
        if bun_eval_flag(flag) && bun_eval_screen::reads_only(program))
}

/// The whole command is `bun -e|--eval|-p|--print <program>` with a screened
/// program: an evaluation with no package operation, environment assignment
/// or wrapper.
pub(super) fn bun_inline_eval(model: &CanonicalCommandV1) -> bool {
    model.confidence == "exact"
        && !model.path_overridden
        && model.wrapper_chain.is_empty()
        && matches!(model.segments.as_slice(), [segment]
            if segment.environment_names.is_empty()
                && segment.wrapper_chain.is_empty()
                && !segment.path_overridden
                && segment.executable.as_deref().map(super::executable_basename) == Some("bun")
                && bun_eval_args(&segment.arguments))
}

/// `python report.py` or `node report.mjs` on Windows: an ordinary workspace
/// script whose source only reads (`script_content::read_only`). Windows has
/// no workspace sandbox to run it in, so it shares the inline evaluation
/// boundary there; a script that writes, launches or imports a package keeps
/// its review. The sink accepts the same names (`contained_argv`).
pub(super) fn windows_script_reason(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> Option<&'static str> {
    use super::script_content::Language;
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || model.segments.len() != 1
    {
        return None;
    }
    let segment = &model.segments[0];
    if !segment.environment_names.is_empty() || segment.pipeline_index != 0 {
        return None;
    }
    let name = crate::program_basename(segment.executable.as_deref()?).to_ascii_lowercase();
    let arguments = segment.arguments.as_slice();
    let (language, script, reason) = if python_runtime_name(&name) {
        let [script, ..] = python_after_isolation_flags(arguments)? else {
            return None;
        };
        (
            Language::Python,
            script,
            "native_python_eval_readonly_containment_required",
        )
    } else if matches!(name.as_str(), "node" | "nodejs") {
        let [script, ..] = node_after_script_flags(arguments) else {
            return None;
        };
        (
            Language::Node,
            script,
            "native_node_eval_readonly_containment_required",
        )
    } else {
        return None;
    };
    let file = script.rsplit('/').next().unwrap_or(script);
    let (stem, extension) = file.rsplit_once('.')?;
    let named = !stem.is_empty()
        && !stem.starts_with('.')
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && match language {
            Language::Python => extension == "py",
            Language::Node => matches!(extension, "js" | "mjs" | "cjs"),
        };
    if !named || !workspace_relative(script) {
        return None;
    }
    let workspace = std::fs::canonicalize(context.cwd?).ok()?;
    let path = std::fs::canonicalize(workspace.join(script)).ok()?;
    (path.starts_with(&workspace)
        && path.is_file()
        && super::script_content::read_only::read_only(language, &path))
    .then_some(reason)
}

/// The script a package-manager command names. npm and Bun need the explicit
/// `run`; pnpm and Yarn also run a script named directly, and a project that
/// documents `pnpm lint` or `yarn build` is spelling the same work. The sink
/// resolves the script body either way, so both spellings reach it together.
/// Subcommands pnpm and Yarn classic run themselves.
///
/// Both managers only fall back to a manifest script when the bare word is not
/// one of their own, so a project that happens to define a `check` or `exec`
/// script does not change what `yarn check` or `pnpm exec` runs. `test` and
/// `start` stay out of this list: those two are the script of that name.
const MANAGER_SUBCOMMANDS: &[&str] = &[
    "add",
    "audit",
    "autoclean",
    "bin",
    "cache",
    "check",
    "config",
    "create",
    "dedupe",
    "deploy",
    "dlx",
    "doctor",
    "env",
    "exec",
    "fetch",
    "generate-lock-entry",
    "global",
    "help",
    "i",
    "import",
    "info",
    "init",
    "install",
    "licenses",
    "link",
    "list",
    "login",
    "logout",
    "ls",
    "node",
    "outdated",
    "owner",
    "pack",
    "patch",
    "pkg",
    "policies",
    "prune",
    "publish",
    "rebuild",
    "remove",
    "rm",
    "root",
    "run",
    "server",
    "setup",
    "store",
    "tag",
    "team",
    "unlink",
    "unplug",
    "up",
    "update",
    "upgrade",
    "upgrade-interactive",
    "version",
    "versions",
    "why",
    "whoami",
    "workspace",
    "workspaces",
];

/// The arguments left after a package manager's spelling of a local-bin run:
/// the workspace's own installed binary, the work `npx` names. `npm x` is
/// npm's documented alias for `npm exec`, and npm documents a `--` before the
/// tool, so the separator belongs to the spelling. `bun exec` runs a shell
/// string rather than a binary, so it is not one of these, and a manager
/// option before the subcommand (`pnpm -r`, `--filter`) fans the run out past
/// one package and keeps the review.
pub(super) fn manager_local_bin_arguments<'a>(
    manager: &str,
    arguments: &'a [String],
) -> Option<&'a [String]> {
    let rest = match (manager, arguments) {
        ("npm", [subcommand, rest @ ..]) if subcommand == "exec" || subcommand == "x" => rest,
        ("pnpm" | "yarn", [subcommand, rest @ ..]) if subcommand == "exec" => rest,
        _ => return None,
    };
    let rest = match rest {
        [separator, rest @ ..] if separator == "--" => rest,
        rest => rest,
    };
    // The sinks run the project's own tool. A manager option before the tool
    // is not a local-bin run.
    rest.first().filter(|tool| !tool.starts_with('-'))?;
    Some(rest)
}

pub(super) fn manager_script_task<'a>(manager: &str, arguments: &'a [String]) -> Option<&'a str> {
    match arguments {
        [run, task] if run == "run" => Some(task.as_str()),
        [task]
            if matches!(manager, "pnpm" | "yarn")
                && !MANAGER_SUBCOMMANDS.contains(&task.as_str()) =>
        {
            Some(task.as_str())
        }
        _ => None,
    }
}

pub(super) fn readonly_test_reason(model: &CanonicalCommandV1) -> Option<&'static str> {
    if requires_pytest_containment(model) {
        return Some("native_pytest_readonly_containment_required");
    }
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || model.segments.len() != 1
    {
        return None;
    }
    let segment = &model.segments[0];
    if !segment.environment_names.is_empty() || segment.pipeline_index != 0 {
        return None;
    }
    let executable = segment.executable.as_deref()?;
    let arguments = segment.arguments.as_slice();
    if executable
        .replace('\\', "/")
        .contains("/node_modules/@esbuild/")
        && executable.ends_with("/bin/esbuild")
        && matches!(arguments, [service, ping] if ping == "--ping"
        && service.strip_prefix("--service=").is_some_and(|version| {
            let parts: Vec<_> = version.split('.').collect();
            parts.len() == 3 && parts.iter().all(|part| !part.is_empty() && part.len() <= 8
                && part.bytes().all(|byte| byte.is_ascii_digit()))
        }))
    {
        // Delegation only: the sink snapshots this local image and executes it
        // inside the same credential-filtering, read-only Vitest boundary.
        return Some("native_vitest_readonly_containment_required");
    }
    let arguments = if matches!(super::executable_basename(executable), "node" | "nodejs") {
        match arguments {
            [flag, rest @ ..] if flag.starts_with("--max-old-space-size=") => {
                let value = flag.strip_prefix("--max-old-space-size=")?;
                if value.is_empty()
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                    || !matches!(value.parse::<u32>(), Ok(16..=131072))
                {
                    return None;
                }
                rest
            }
            rest => rest,
        }
    } else {
        arguments
    };
    match (super::executable_basename(executable), arguments) {
        (name, args)
            if python_runtime_name(name)
                && (python_inline_eval_args(args)
                    || python_test_script_args(args)
                    || python_unittest_args(args)) =>
        {
            return Some("native_python_eval_readonly_containment_required");
        }
        ("node" | "nodejs", [flag, _program]) if matches!(flag.as_str(), "-e" | "--eval") => {
            return Some("native_node_eval_readonly_containment_required");
        }
        // Same evaluation boundary as Node; the sink approves the Bun image.
        ("bun", args) if bun_eval_args(args) => return Some(BUN_EVAL_REASON),
        (name, args) if tsx_test_script_args(name, args) => {
            return Some("native_vitest_readonly_containment_required");
        }
        ("node" | "nodejs", args) if node_test_script_args(args) => {
            return Some("native_node_eval_readonly_containment_required");
        }
        _ => {}
    }
    if matches!(
        super::executable_basename(executable),
        "npm" | "pnpm" | "bun" | "yarn"
    ) {
        let rest = match arguments {
            [test, rest @ ..] if test == "test" => Some(rest),
            [run, test, rest @ ..] if run == "run" && test == "test" => Some(rest),
            _ => None,
        };
        if rest.is_some_and(|rest| rest.is_empty() || rest.first().is_some_and(|arg| arg == "--")) {
            // This is only a routing receipt. The sink resolves the manifest,
            // rejects lifecycle/shell effects and checks the underlying runner.
            return Some("native_package_test_readonly_containment_required");
        }
    }
    // `bun x` is Bun's spelling of `bunx`; the later proofs read it as one.
    // Bun takes `--cwd` only before `x`, so a later one is not unwrapped.
    // `npm exec`, `npm x`, `yarn exec` and `pnpm exec` are each a manager's
    // spelling of the same local-bin run `npx` names, so they read as `npx`.
    // Windows hands over the resolved image, `node.exe` for `node`. One name
    // for the program keeps every route below reading the same command.
    let (executable, arguments) = if let Some(rest) =
        manager_local_bin_arguments(crate::program_basename(executable), arguments)
    {
        ("npx", rest)
    } else {
        match arguments {
            [wrapper, no_install, rest @ ..]
                if crate::program_basename(executable) == "bun"
                    && wrapper == "x"
                    && no_install == "--no-install"
                    && !rest.first().is_some_and(|word| word.starts_with("--cwd")) =>
            {
                ("bunx", rest)
            }
            [wrapper, rest @ ..]
                if crate::program_basename(executable) == "bun"
                    && wrapper == "x"
                    && !rest.first().is_some_and(|word| word.starts_with("--cwd")) =>
            {
                ("bunx", rest)
            }
            _ => (crate::program_basename(executable), arguments),
        }
    };
    let build = match executable {
        "bun" | "npm" | "pnpm" | "yarn" => {
            manager_script_task(executable, arguments) == Some("build")
        }
        "bunx" | "npx" => {
            matches!(arguments, [tool, task, ..] if tool == "vite" && task == "build")
        }
        "vite" => arguments.first().is_some_and(|arg| arg == "build"),
        "node" | "nodejs" => {
            matches!(arguments, [entry, task, ..] if local_package_entry(entry, "vite/bin/vite.js") && task == "build")
        }
        _ => false,
    };
    if build {
        return Some("native_node_build_output_containment_required");
    }
    let read_only_node_tool = match executable {
        // The script body is what runs, not the name a project chose for it:
        // `format:check` and `ci:lint` are the work `lint` is. The route below
        // reads the manifest and keeps this only for a body the sink runs.
        "bun" | "npm" | "pnpm" | "yarn" => manager_script_task(executable, arguments).is_some(),
        "bunx" | "npx" => {
            matches!(arguments, [tool, rest @ ..] if tool == "eslint" || (tool == "tsc" && rest.iter().any(|arg| arg == "--noEmit")) || (tool == "prettier" && prettier_checks(rest)))
        }
        "eslint" => true,
        "tsc" => arguments.iter().any(|arg| arg == "--noEmit"),
        "prettier" => prettier_checks(arguments),
        "node" | "nodejs" => {
            matches!(arguments, [entry, rest @ ..] if local_package_entry(entry, "eslint/bin/eslint.js") || (local_package_entry(entry, "typescript/bin/tsc") && rest.iter().any(|arg| arg == "--noEmit")) || (PRETTIER_ENTRIES.iter().any(|name| local_package_entry(entry, name)) && prettier_checks(rest)))
        }
        _ => false,
    };
    if read_only_node_tool
        && !arguments.iter().any(|arg| {
            matches!(
                arg.as_str(),
                "--fix"
                    | "--fix-dry-run"
                    | "--output-file"
                    | "-o"
                    | "--emitDeclarationOnly"
                    | "--write"
                    | "-w"
            ) || arg.starts_with("--output-file=")
                || arg.starts_with("--fix=")
                || arg.starts_with("--write=")
        })
    {
        return Some("native_node_tool_readonly_containment_required");
    }
    if super::executable_basename(executable) == "git"
        && super::git_helper_context::git_helper_context_required(
            model,
            super::PathContext::default(),
        )
    {
        return Some("native_git_readonly_containment_required");
    }
    let vitest = match super::executable_basename(executable) {
        "bun" => {
            let arguments = match arguments {
                [flag, directory, rest @ ..]
                    if flag == "--cwd" && !directory.is_empty() && !directory.starts_with('-') =>
                {
                    rest
                }
                [flag, rest @ ..] if flag.starts_with("--cwd=") && flag.len() > 6 => rest,
                rest => rest,
            };
            matches!(arguments, [wrapper, tool, run, ..] if wrapper == "x" && tool == "vitest" && run == "run")
                || matches!(arguments, [wrapper, flag, tool, run, ..] if wrapper == "x" && flag == "--no-install" && tool == "vitest" && run == "run")
        }
        "bunx" | "npx" => {
            let arguments = match arguments {
                [flag, directory, rest @ ..]
                    if executable_is_bunx(executable)
                        && flag == "--cwd"
                        && workspace_relative(directory) =>
                {
                    rest
                }
                [flag, rest @ ..]
                    if executable_is_bunx(executable)
                        && flag.strip_prefix("--cwd=").is_some_and(workspace_relative) =>
                {
                    rest
                }
                rest => rest,
            };
            matches!(arguments, [tool, run, ..] if tool == "vitest" && run == "run")
                || matches!(arguments, [flag, tool, run, ..] if flag == "--no-install" && tool == "vitest" && run == "run")
        }
        "vitest" => arguments.first().is_some_and(|arg| arg == "run"),
        "node" | "nodejs" => {
            matches!(arguments, [entry, run, ..] if entry.replace('\\', "/").contains("/node_modules/vitest/") && entry.ends_with("/vitest.mjs") && run == "run")
        }
        _ => false,
    };
    if vitest {
        return Some("native_vitest_readonly_containment_required");
    }
    if matches!(super::executable_basename(executable), "node" | "nodejs")
        && arguments
            .first()
            .is_some_and(|argument| argument == "--test")
    {
        return Some("native_node_test_readonly_containment_required");
    }
    None
}

/// `node node_modules/<entry>` and `node <dir>/node_modules/<entry>`. The sink
/// still proves the file is the project's own installed entrypoint.
fn local_package_entry(entry: &str, package_entry: &str) -> bool {
    entry
        .strip_suffix(package_entry)
        .and_then(|prefix| prefix.strip_suffix("node_modules/"))
        .is_some_and(|prefix| prefix.is_empty() || prefix.ends_with('/'))
}
