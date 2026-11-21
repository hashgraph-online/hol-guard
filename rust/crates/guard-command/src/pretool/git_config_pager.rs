//! Whether the agent's environment turns Git's pager off.

pub(super) fn environment_pager_disabled(
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<bool> {
    match execution_environment {
        Some(context) => {
            if context
                .environment_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("GIT_PAGER"))
            {
                Some(context.git_pager_disabled)
            } else if context
                .environment_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("PAGER"))
            {
                Some(context.pager_disabled)
            } else {
                None
            }
        }
        None => std::env::var_os("GIT_PAGER")
            .map(|value| value.is_empty() || value.to_string_lossy() == "cat")
            .or_else(|| {
                std::env::var_os("PAGER")
                    .map(|value| value.is_empty() || value.to_string_lossy() == "cat")
            }),
    }
}

pub(super) fn git_pager_disabled(
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    match execution_environment {
        Some(context) => {
            context
                .environment_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("GIT_PAGER"))
                && context.git_pager_disabled
        }
        None => std::env::var_os("GIT_PAGER")
            .is_some_and(|value| value.is_empty() || value.to_string_lossy() == "cat"),
    }
}
