use crate::CanonicalCommandV1;

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
    if super::executable_basename(executable) == "git" && super::git_helper_context_required(model)
    {
        return Some("native_git_readonly_containment_required");
    }
    let vitest = match super::executable_basename(executable) {
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
        && segment
            .arguments
            .first()
            .is_some_and(|argument| argument == "--test")
    {
        return Some("native_node_test_readonly_containment_required");
    }
    None
}
