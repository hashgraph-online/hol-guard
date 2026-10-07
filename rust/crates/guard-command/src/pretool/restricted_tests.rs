use crate::CanonicalCommandV1;

fn python_runtime_name(name: &str) -> bool {
    name.strip_prefix("python").is_some_and(|suffix| {
        suffix.is_empty()
            || suffix
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

fn python_inline_eval_args(arguments: &[String]) -> bool {
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
            return false;
        }
        flags |= bits;
        rest = &rest[1..];
    }
    matches!(rest, [flag, _program] if flag == "-c")
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
        (name, args) if python_runtime_name(name) && python_inline_eval_args(args) => {
            return Some("native_python_eval_readonly_containment_required");
        }
        ("node" | "nodejs", [flag, _program]) if matches!(flag.as_str(), "-e" | "--eval") => {
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
    let build = match super::executable_basename(executable) {
        "bun" | "npm" | "pnpm" => {
            matches!(arguments, [run, task] if run == "run" && task == "build")
        }
        "bunx" | "npx" => {
            matches!(arguments, [tool, task, ..] if tool == "vite" && task == "build")
        }
        "vite" => arguments.first().is_some_and(|arg| arg == "build"),
        "node" | "nodejs" => {
            matches!(arguments, [entry, task, ..] if entry.ends_with("/node_modules/vite/bin/vite.js") && task == "build")
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
            matches!(arguments, [entry, rest @ ..] if entry.ends_with("/node_modules/eslint/bin/eslint.js") || (entry.ends_with("/node_modules/typescript/bin/tsc") && rest.iter().any(|arg| arg == "--noEmit")))
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
        && super::git_helper_context::git_helper_context_required(model)
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
