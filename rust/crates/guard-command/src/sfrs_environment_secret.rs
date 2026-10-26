//! Process-environment secret request
//! (`secret_file_request_services/environment_secret_dump.py`).
//!
//! The Python module only transported a classification the native context
//! already produced. The classifier itself is
//! [`crate::environment_secret_dump`]; this wrapper maps its verdict to the
//! request match and keeps the fail-closed error for an unusable verdict.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;

use crate::environment_secret_dump::command_reads_environment_secrets_with_caller_cwd;
use crate::sfrs_tool_request::ToolActionRequest;

pub(crate) const ACTION_CLASS: &str = "process environment secret read";
pub(crate) const REASON: &str = "Guard treats commands that print process environment secrets as sensitive because they can expose cloud keys and credentials to the agent.";

/// `environment_secret_dump_request`. `Err` is the Python `ValueError` for a
/// classification that is unavailable or invalid.
pub(crate) fn environment_secret_dump_request(
    tool_name: &str,
    normalized_tool_name: &str,
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    fallback_cwd: Option<&Path>,
) -> Result<Option<ToolActionRequest>, &'static str> {
    let dump = command_reads_environment_secrets_with_caller_cwd(
        command_text,
        cwd,
        home_dir,
        fallback_cwd,
    )
    .map_err(|_| "native_environment_secret_dump_unavailable:invalid_result")?;
    Ok(dump.then(|| {
        ToolActionRequest::new(
            tool_name,
            normalized_tool_name,
            command_text,
            ACTION_CLASS,
            REASON,
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_commands_become_requests() {
        let found = environment_secret_dump_request("Bash", "bash", "printenv", None, None, None)
            .expect("verdict")
            .expect("request");
        assert_eq!(found.tool_name, "Bash");
        assert_eq!(found.normalized_tool_name, "bash");
        assert_eq!(found.command_text, "printenv");
        assert_eq!(found.action_class, ACTION_CLASS);
        assert_eq!(found.reason, REASON);
    }

    #[test]
    fn printenv_of_named_plain_variables_prints_no_secret() {
        use crate::environment_secret_dump::printenv_may_print_secret;
        for command in [
            "printenv path",
            "printenv home shell && ls",
            "echo printenv path",
        ] {
            assert!(!printenv_may_print_secret(command), "{command}");
        }
        for command in [
            "printenv",
            "printenv | grep x",
            "printenv -0",
            "printenv github_token",
            "printenv path aws_secret_access_key",
            "printenv \"$name\"",
            "printenv path; printenv",
        ] {
            assert!(printenv_may_print_secret(command), "{command}");
        }
    }

    #[test]
    fn harmless_and_empty_commands_are_not_requests() {
        for command in ["echo hi", "", "   ", "é"] {
            let verdict =
                environment_secret_dump_request("Bash", "bash", command, None, None, None);
            assert!(matches!(verdict, Ok(None)), "{command:?}");
        }
    }
}
