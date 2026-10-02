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
