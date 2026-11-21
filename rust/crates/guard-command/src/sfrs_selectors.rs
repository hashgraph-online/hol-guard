//! Small static request checks: GitHub selector shapes, Python and pytest
//! entry points, and the tool-action risk summary
//! (`github_selector_patterns.py`, `python_pytest_entrypoints.py`,
//! `tool_action_risk_summaries.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;

use crate::hook_adapter_pytext::compile_fancy;
use crate::sfrs_constants::PYTHON_INTERPRETER_OPTIONS_WITH_VALUES;

static REPOSITORY_COMPONENT: LazyLock<FancyRegex> =
    LazyLock::new(|| compile_fancy(r"\A[A-Za-z0-9_.-]+\z"));
static PR_HEAD_OID_ENDPOINT: LazyLock<FancyRegex> = LazyLock::new(|| {
    compile_fancy(concat!(
        r"\Arepos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/commits/",
        r"\$\(gh pr view [1-9][0-9]* --json headRefOid --jq \.headRefOid\)",
        r"/check-runs(?:\?[A-Za-z0-9_.=&-]+)?\z"
    ))
});

/// `github_repository_selector_is_safe`.
pub(crate) fn github_repository_selector_is_safe(selector: &str) -> bool {
    if ["$", "`", "$(", "${"]
        .iter()
        .any(|marker| selector.contains(marker))
    {
        return false;
    }
    let mut parts: Vec<&str> = selector.split('/').collect();
    if parts.len() == 3 {
        if parts[0].to_lowercase() != "github.com" {
            return false;
        }
        parts.remove(0);
    }
    parts.len() == 2
        && parts
            .iter()
            .all(|part| REPOSITORY_COMPONENT.is_match(part).unwrap_or(false))
}

/// `github_pr_head_oid_endpoint_matches`.
pub(crate) fn github_pr_head_oid_endpoint_matches(value: &str) -> bool {
    PR_HEAD_OID_ENDPOINT.is_match(value).unwrap_or(false)
}

fn module_root(module: &str) -> &str {
    module.split('.').next().unwrap_or("")
}

/// `_python_segment_targets_module`.
pub(crate) fn python_segment_targets_module(args: &[String], root: &str) -> bool {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--" {
            return false;
        }
        if arg == "-c"
            || arg == "--command"
            || arg.starts_with("-c")
            || arg.starts_with("--command=")
        {
            return false;
        }
        if arg == "-m" {
            let module = args.get(index + 1).map_or("", String::as_str);
            return module_root(module) == root;
        }
        if arg.starts_with("-m") && arg.chars().count() > 2 {
            return module_root(&arg[2..]) == root;
        }
        if PYTHON_INTERPRETER_OPTIONS_WITH_VALUES.contains(&arg) {
            index += 2;
            continue;
        }
        if PYTHON_INTERPRETER_OPTIONS_WITH_VALUES
            .iter()
            .any(|option| arg.starts_with(option) && arg.len() > option.len())
        {
            index += 1;
            continue;
        }
        if !arg.starts_with('-') {
            return false;
        }
        index += 1;
    }
    false
}

/// `_pytest_args_from_python`.
pub(crate) fn pytest_args_from_python(command_args: &[String]) -> Option<Vec<String>> {
    let mut index = 0;
    while index < command_args.len() {
        let token = command_args[index].as_str();
        if token == "-m" && index + 1 < command_args.len() {
            return (module_root(&command_args[index + 1]) == "pytest")
                .then(|| command_args[index + 2..].to_vec());
        }
        if token.starts_with("-m") && token.chars().count() > 2 {
            return (module_root(&token[2..]) == "pytest")
                .then(|| command_args[index + 1..].to_vec());
        }
        if PYTHON_INTERPRETER_OPTIONS_WITH_VALUES.contains(&token) {
            index += 2;
            continue;
        }
        index += 1;
    }
    None
}

/// `tool_action_risk_summary` for an action class and reason.
pub(crate) fn tool_action_risk_summary(action_class: &str, reason: &str) -> String {
    if action_class.to_lowercase() == "destructive shell command" {
        return "This destructive shell command can delete or overwrite local files, discard \
                work, or alter repository or system state. Recovery may require version control \
                or a backup."
            .to_owned();
    }
    format!(
        "Sensitive native tool action ({action_class}): {}.",
        reason.trim_end_matches('.')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn repository_selectors() {
        assert!(github_repository_selector_is_safe("owner/repo"));
        assert!(github_repository_selector_is_safe("GitHub.com/owner/repo"));
        assert!(!github_repository_selector_is_safe("evil.com/owner/repo"));
        assert!(!github_repository_selector_is_safe("owner/$(x)"));
    }

    #[test]
    fn head_oid_endpoint_shape() {
        assert!(github_pr_head_oid_endpoint_matches(
            "repos/o/r/commits/$(gh pr view 12 --json headRefOid --jq .headRefOid)/check-runs?per_page=100"
        ));
        assert!(!github_pr_head_oid_endpoint_matches(
            "repos/o/r/commits/abc/check-runs"
        ));
    }

    #[test]
    fn python_module_entry_points() {
        assert!(python_segment_targets_module(
            &args(&["-m", "pytest.x"]),
            "pytest"
        ));
        assert!(!python_segment_targets_module(
            &args(&["-c", "x"]),
            "pytest"
        ));
        assert_eq!(
            pytest_args_from_python(&args(&["-m", "pytest", "-q"])),
            Some(args(&["-q"]))
        );
        assert_eq!(pytest_args_from_python(&args(&["-m", "other"])), None);
    }

    #[test]
    fn risk_summary_shapes() {
        assert!(tool_action_risk_summary("Destructive Shell Command", "x")
            .starts_with("This destructive"));
        assert_eq!(
            tool_action_risk_summary("write", "Because."),
            "Sensitive native tool action (write): Because."
        );
    }
}
