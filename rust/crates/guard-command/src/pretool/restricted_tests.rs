use crate::CanonicalCommandV1;

#[path = "bun_eval_screen.rs"]
mod bun_eval_screen;

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
        "npm" | "pnpm" | "bun"
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
    let (executable, arguments) = match arguments {
        [wrapper, no_install, rest @ ..]
            if super::executable_basename(executable) == "bun"
                && wrapper == "x"
                && no_install == "--no-install"
                && !rest.first().is_some_and(|word| word.starts_with("--cwd")) =>
        {
            ("bunx", rest)
        }
        [wrapper, rest @ ..]
            if super::executable_basename(executable) == "bun"
                && wrapper == "x"
                && !rest.first().is_some_and(|word| word.starts_with("--cwd")) =>
        {
            ("bunx", rest)
        }
        _ => (executable, arguments),
    };
    let build = match super::executable_basename(executable) {
        "bun" | "npm" | "pnpm" => {
            matches!(arguments, [run, task] if run == "run" && task == "build")
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
    let read_only_node_tool = match super::executable_basename(executable) {
        "bun" | "npm" | "pnpm" => {
            matches!(arguments, [run, task] if run == "run" && matches!(task.as_str(), "lint" | "typecheck"))
        }
        "bunx" | "npx" => {
            matches!(arguments, [tool, rest @ ..] if tool == "eslint" || (tool == "tsc" && rest.iter().any(|arg| arg == "--noEmit")))
        }
        "eslint" => true,
        "tsc" => arguments.iter().any(|arg| arg == "--noEmit"),
        "node" | "nodejs" => {
            matches!(arguments, [entry, rest @ ..] if local_package_entry(entry, "eslint/bin/eslint.js") || (local_package_entry(entry, "typescript/bin/tsc") && rest.iter().any(|arg| arg == "--noEmit")))
        }
        _ => false,
    };
    if read_only_node_tool
        && !arguments.iter().any(|arg| {
            matches!(
                arg.as_str(),
                "--fix" | "--fix-dry-run" | "--output-file" | "-o" | "--emitDeclarationOnly"
            ) || arg.starts_with("--output-file=")
                || arg.starts_with("--fix=")
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
        // pnpm's spelling of a local-bin run. A pnpm option before the tool
        // (`-c` runs a shell, `-r`/`--filter` fan out) keeps the review.
        "pnpm" => {
            matches!(arguments, [exec, tool, run, ..] if exec == "exec" && tool == "vitest" && run == "run")
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
