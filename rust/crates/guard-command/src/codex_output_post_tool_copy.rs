//! Request, summary and reason copy for a credential-looking post-tool output
//! (`commands_support_codex_tool_output_messages.py`).

/// What the copy describes about one flagged output.
pub(crate) struct OutputCopy<'a> {
    pub(crate) harness_label: &'a str,
    pub(crate) local_secret_source: Option<&'a str>,
    pub(crate) merged_output_capture: bool,
    pub(crate) focused_pytest: bool,
}

/// `_codex_tool_output_request_summary`.
pub(crate) fn request_summary(copy: &OutputCopy, tool_name: &str, command_text: &str) -> String {
    let harness = copy.harness_label;
    if let Some(source) = copy.local_secret_source {
        return format!(
            "{harness} tool `{tool_name}` read local secrets from {source} while running `{command_text}`."
        );
    }
    match (copy.focused_pytest, copy.merged_output_capture) {
        (true, true) => format!(
            "{harness} tool `{tool_name}` ran focused pytest, merged stderr into stdout while running \
             `{command_text}`, and the captured output looked credential-like."
        ),
        (true, false) => format!(
            "{harness} tool `{tool_name}` ran focused pytest and produced credential-looking output while \
             running `{command_text}`."
        ),
        (false, true) => format!(
            "{harness} tool `{tool_name}` merged stderr into stdout while running `{command_text}`, \
             and the captured output looked credential-like."
        ),
        (false, false) => format!(
            "{harness} tool `{tool_name}` produced credential-looking output while running `{command_text}`."
        ),
    }
}

/// `_codex_tool_output_runtime_summary`.
pub(crate) fn runtime_summary(copy: &OutputCopy) -> String {
    let harness = copy.harness_label;
    if let Some(source) = copy.local_secret_source {
        return format!("Local secrets from {source} reached {harness} tool output.");
    }
    match (copy.focused_pytest, copy.merged_output_capture) {
        (true, true) => format!(
            "Focused pytest merged stderr into stdout and emitted credential-looking output before it reached \
             {harness}. Pytest can execute repository-controlled code, so this could be a real local secret."
        ),
        (true, false) => format!(
            "Focused pytest emitted credential-looking output before it reached {harness}. \
             Pytest can execute repository-controlled code, so this could be a real local secret."
        ),
        (false, true) => {
            format!("Combined stdout/stderr looked credential-like before it reached {harness}.")
        }
        (false, false) => format!(
            "Requests a sensitive native tool action: credential-looking output reached {harness}."
        ),
    }
}

/// `_codex_tool_output_runtime_reason`.
pub(crate) fn runtime_reason(copy: &OutputCopy) -> String {
    let harness = copy.harness_label;
    if copy.local_secret_source.is_some() {
        return format!(
            "Guard inspects supported {harness} tool output before {harness} uses it, \
             so accidental secret reads can be \
             stopped even when the filename was not obviously sensitive."
        );
    }
    match (copy.focused_pytest, copy.merged_output_capture) {
        (true, true) => format!(
            "Guard stopped this pytest output because pytest executes repository-controlled code, and merging stderr \
             into stdout can forward real local secrets to {harness}. \
             If you only need the exit status, rerun without \
             `2>&1` or keep stderr out of model-visible output."
        ),
        (true, false) => "Guard stopped this pytest output because pytest executes repository-controlled code. \
             Credential-looking output could be a real local secret printed by the test, not just fixture text."
            .to_owned(),
        (false, true) => format!(
            "Guard stopped this command shape because merging stderr into stdout can send credential-looking failure \
             output to {harness}. If you only need the exit status, rerun without `2>&1` or keep stderr out of \
             the \
             model-visible output."
        ),
        (false, false) => format!(
            "Guard inspects supported {harness} tool output before {harness} uses it, \
             so accidental secret reads can be stopped \
             even when the filename was not obviously sensitive."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{request_summary, runtime_reason, runtime_summary, OutputCopy};

    #[test]
    fn focused_pytest_copy_labels_the_harness() {
        let copy = OutputCopy {
            harness_label: "Pi",
            local_secret_source: None,
            merged_output_capture: true,
            focused_pytest: true,
        };
        let command = "python3 -m pytest tests/test_smoke.py::test_release -q 2>&1";
        assert_eq!(
            request_summary(&copy, "Bash", command),
            "Pi tool `Bash` ran focused pytest, merged stderr into stdout while running \
             `python3 -m pytest tests/test_smoke.py::test_release -q 2>&1`, and the captured output \
             looked credential-like."
        );
        assert_eq!(
            runtime_summary(&copy),
            "Focused pytest merged stderr into stdout and emitted credential-looking output before \
             it reached Pi. Pytest can execute repository-controlled code, so this could be a real \
             local secret."
        );
        assert_eq!(
            runtime_reason(&copy),
            "Guard stopped this pytest output because pytest executes repository-controlled code, \
             and merging stderr into stdout can forward real local secrets to Pi. If you only need \
             the exit status, rerun without `2>&1` or keep stderr out of model-visible output."
        );
    }
}
