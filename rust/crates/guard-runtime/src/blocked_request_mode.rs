//! `safe_alternative_reason` from `blocked_request_mode.py`: the deny text a
//! safe-alternative blocked request returns to the agent.

use crate::guard_store_json::py_strip;

/// `SAFE_ALTERNATIVE_GUIDANCE`.
const SAFE_ALTERNATIVE_GUIDANCE: &str = "This action remains blocked. Continue with a safe, \
     permitted alternative that respects the same protection. Do not retry an equivalent \
     command, bypass Guard, or seek permission to run it. If no safe alternative can complete \
     the task, explain the limitation.";
/// `_APPROVAL_WAIT`.
const APPROVAL_WAIT: &str = "It is waiting for the user to approve it in the HOL Guard inbox \
     (`hol-guard approvals`). Do not retry the same action until it is approved; continue with \
     other work meanwhile.";
/// `_NOT_QUEUED`.
const NOT_QUEUED: &str = "No approval is waiting in HOL Guard for this action. Do not retry the \
     same action or work around the block; continue with a permitted alternative or tell the user what is \
     blocked.";
const APPROVAL_ALWAYS_ONLY: &str = "It is waiting in the HOL Guard inbox (`hol-guard approvals`), but approving it just once will not \
     let you run it; only \"Always allow exact action\" will. Do not retry it unless the user says they \
     chose that; continue with other work meanwhile.";
const APPROVAL_CANNOT_UNBLOCK: &str =
    "It is recorded in the HOL Guard inbox, but approving it there will not let you run it. \
     Do not retry this exact command. Tell the user exactly what is blocked so they can run it themselves, \
     or continue with a permitted alternative.";
/// `_INBOX_APPROVAL_OFFER`: the native review text's offer of inbox approval,
/// dropped when no approval can let the action run.
const INBOX_APPROVAL_OFFER: &str = " Approve it in the HOL Guard inbox (choose Always for a \
     repeated read-only command), or split it into simpler commands.";

/// `_CONNECTOR_SETUP_WAIT`: an MCP server setup review is one decision for
/// the server, not an approval of this action. Only the vector-checked
/// `connector_setup_reason` reads it until the resident renders this text.
#[cfg_attr(not(test), allow(dead_code))]
const CONNECTOR_SETUP_WAIT: &str = "Setting it up is a one-time decision for the user in the HOL \
     Guard inbox (`hol-guard approvals`), not an approval of this action. Do not retry it, in this \
     or another spelling, until it is set up; continue with other work meanwhile.";
/// `_CONNECTOR_APPROVAL_WAIT`: a local CLI or script Guard has not been set
/// up for is an ordinary review, which the user's Allow once or Always allow
/// releases.
#[cfg_attr(not(test), allow(dead_code))]
const CONNECTOR_APPROVAL_WAIT: &str = "It is waiting for the user to approve it in the HOL Guard \
     inbox (`hol-guard approvals`), where Allow once or Always allow lets it run. Do not retry \
     the same action until it is approved; continue with other work meanwhile.";
/// `CONNECTOR_SETUP_REASON_PREFIX`.
const CONNECTOR_SETUP_REASON_PREFIX: &str = "HOL Guard has not been set up for `";

/// `connector_setup_reason(name, surface, ask=..., permitted=..., approvable=...)`:
/// a local CLI or script whose review is `approvable` says it waits for the
/// user's approval in either mode, and the caller adds the link. Otherwise,
/// and for an MCP server, the default mode names the computed redirect (if
/// any) and appends `SAFE_ALTERNATIVE_GUIDANCE`, with no link and no request
/// to ask the user; `ask` mode says it waits in the inbox, and the caller adds
/// the link.
/// The resident has no caller yet: the daemon renders this text and the vector
/// test keeps the two byte-identical until the resident takes over rendering.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn connector_setup_reason(
    name: &str,
    surface: &str,
    ask: bool,
    permitted: &[&str],
    approvable: bool,
) -> String {
    let label = match surface {
        "cli" => "local CLI",
        "package-scripts" => "package script",
        "mcp" => "MCP server",
        other => other,
    };
    let reason = format!("{CONNECTOR_SETUP_REASON_PREFIX}{name}` ({label}) on this device.");
    if approvable && matches!(surface, "cli" | "package-scripts") {
        return format!("{reason} {CONNECTOR_APPROVAL_WAIT}");
    }
    if ask {
        return format!("{reason} {CONNECTOR_SETUP_WAIT}");
    }
    let names = permitted
        .iter()
        .filter(|item| !item.is_empty())
        .map(|item| format!("`{item}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let redirect = if names.is_empty() {
        String::new()
    } else {
        format!("Permitted on this device: {names}.")
    };
    [
        reason.as_str(),
        redirect.as_str(),
        SAFE_ALTERNATIVE_GUIDANCE,
    ]
    .into_iter()
    .filter(|part| !part.is_empty())
    .collect::<Vec<_>>()
    .join(" ")
}

/// `is_unlinked_connector_setup_reason`: a default-mode connector setup
/// reason, to which a harness renderer adds no approval link or step.
pub(crate) fn is_unlinked_connector_setup_reason(text: &str) -> bool {
    text.contains(CONNECTOR_SETUP_REASON_PREFIX) && text.contains(SAFE_ALTERNATIVE_GUIDANCE)
}

/// `_BUILD_REVIEW_PREFIX`: a package review of a build or test says why in
/// its own text, and the install hint does not apply to it.
const BUILD_REVIEW_PREFIX: &str = "HOL Guard requires review before this build or test command";

/// `_READ_REVIEW_PREFIX`: a review of a direct read of one path says why in
/// its own text, and the advice for narrowing a search does not apply to it.
const READ_REVIEW_PREFIX: &str = "HOL Guard requires review before this file read";

/// `_REASON_CODE_HINTS`: plain-language next steps keyed by the native
/// decision's reason code; unknown codes have none.
fn reason_code_hint(reason_code: &str) -> &'static str {
    match reason_code {
        "native_destructive_command" => {
            "This command deletes or overwrites data. Use `git worktree remove` for a worktree, \
             or target one specific path."
        }
        "native_package_review" => {
            "Package installs download code from a registry, so Guard reviews them. An install \
             that only restores the committed lockfile and runs no scripts (`bun install \
             --frozen-lockfile --ignore-scripts`, `pnpm install --frozen-lockfile \
             --ignore-scripts` or `npm ci --ignore-scripts`) can proceed once Guard has checked \
             the lockfile and settings. If this was already that form, reuse dependencies that \
             are already installed where you can."
        }
        "native_network_review" => "This makes a network request that Guard has not seen before.",
        "native_file_read_review" => {
            "This reads a file outside what Guard treats as safe to read. A search is checked \
             against every file it can reach, so search a narrower folder or one file, use `rg` \
             with a `-g` file filter, or find files by name with `find` or `glob`."
        }
        "native_pre_tool_unknown_review" => {
            "Guard cannot check what this tool call will do before it runs."
        }
        "native_command_review_required" => {
            "Guard could not prove this exact command is read-only. Use a simpler built-in tool \
             where one fits. If it chains several steps, run each step as its own command; Guard \
             checks each one on its own."
        }
        _ => "",
    }
}

/// `safe_alternative_reason(reason, reason_code=..., approval_queued=...)`.
pub(crate) fn safe_alternative_reason(
    reason: &str,
    reason_code: Option<&str>,
    approval_queued: Option<bool>,
) -> String {
    safe_alternative_reason_with_retry(reason, reason_code, approval_queued, true, false)
}

pub(crate) fn safe_alternative_reason_with_retry(
    reason: &str,
    reason_code: Option<&str>,
    approval_queued: Option<bool>,
    retry_reuses_approval: bool,
    exact_action_allowable: bool,
) -> String {
    let reason = py_strip(reason);
    if reason_code.is_none() && approval_queued.is_none() {
        return py_strip(&format!("{reason} {SAFE_ALTERNATIVE_GUIDANCE}")).to_owned();
    }
    let hint = if reason.starts_with(BUILD_REVIEW_PREFIX) || reason.starts_with(READ_REVIEW_PREFIX)
    {
        ""
    } else {
        reason_code_hint(reason_code.unwrap_or_default())
    };
    let wait = if approval_queued != Some(true) {
        NOT_QUEUED
    } else if retry_reuses_approval {
        APPROVAL_WAIT
    } else if exact_action_allowable {
        APPROVAL_ALWAYS_ONLY
    } else {
        APPROVAL_CANNOT_UNBLOCK
    };
    let reason = if wait == NOT_QUEUED || wait == APPROVAL_CANNOT_UNBLOCK {
        reason.replace(INBOX_APPROVAL_OFFER, "")
    } else {
        reason.to_owned()
    };
    [reason.as_str(), hint, wait]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_setup_reason_matches_the_python_vectors_byte_for_byte() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../testdata/connector_setup_reason_vectors.json"
        ))
        .expect("vectors");
        for case in vectors.as_array().expect("cases") {
            let permitted: Vec<&str> = case["permitted"]
                .as_array()
                .expect("permitted")
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect();
            let text = connector_setup_reason(
                case["name"].as_str().expect("name"),
                case["surface"].as_str().expect("surface"),
                case["ask"].as_bool().expect("ask"),
                &permitted,
                case["approvable"].as_bool().expect("approvable"),
            );
            assert_eq!(text, case["text"].as_str().expect("text"));
            let unlinked = case["unlinked"].as_bool().expect("unlinked");
            assert_eq!(
                is_unlinked_connector_setup_reason(&text),
                unlinked,
                "{text}"
            );
            assert!(!text.contains("http"), "{text}");
            assert_eq!(
                text.ends_with(SAFE_ALTERNATIVE_GUIDANCE),
                unlinked,
                "{text}"
            );
            assert_eq!(
                text.contains("hol-guard approvals"),
                !unlinked,
                "an unlinked text never points at the inbox: {text}"
            );
        }
    }

    #[test]
    fn review_drops_the_inbox_offer_only_when_approval_cannot_let_it_run() {
        let native = "HOL Guard requires review because this command could not be confirmed \
             read-only. Approve it in the HOL Guard inbox (choose Always for a repeated read-only \
             command), or split it into simpler commands.";
        for (queued, reuses, offered) in [
            (true, false, false),
            (false, true, false),
            (true, true, true),
        ] {
            let text = safe_alternative_reason_with_retry(
                native,
                Some("native_command_review_required"),
                Some(queued),
                reuses,
                false,
            );
            assert!(text.starts_with(
                "HOL Guard requires review because this command could not be confirmed read-only."
            ));
            assert_eq!(text.contains("Approve it in the HOL Guard inbox"), offered);
        }
    }

    #[test]
    fn a_direct_read_review_leaves_out_the_search_advice() {
        let read = "HOL Guard requires review before this file read can execute. `src/lib/auth` \
             is named like a credential store, so Guard holds a read of it.";
        let text = safe_alternative_reason(read, Some("native_file_read_review"), Some(true));
        assert!(text.starts_with(read));
        assert!(!text.contains("A search is checked"), "{text}");
        let search = safe_alternative_reason(
            "HOL Guard requires review before this file action can execute.",
            Some("native_file_read_review"),
            Some(true),
        );
        assert!(search.contains("A search is checked"), "{search}");
    }

    #[test]
    fn a_build_review_leaves_out_the_install_hint() {
        let build = "HOL Guard requires review before this build or test command can execute, \
             because it can download dependencies and run their build scripts.";
        let text = safe_alternative_reason(build, Some("native_package_review"), Some(true));
        assert!(text.starts_with(build));
        assert!(!text.contains("--ignore-scripts"), "{text}");
        let install = safe_alternative_reason(
            "HOL Guard requires review before this package or script command can execute.",
            Some("native_package_review"),
            Some(true),
        );
        assert!(install.contains("--ignore-scripts"), "{install}");
    }
}
