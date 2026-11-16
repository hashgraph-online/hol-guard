//! Whether one inline `-c <key>=<value>` leaves a Git read Guard proved.

use super::git_hooks_path::hooks_path_names_no_hooks;

/// Whether one `-c <key>=<value>` before the subcommand leaves the read Guard
/// proved.
///
/// Git takes the setting for this one command, so the question is not whether
/// the value is sensible but whether it can change what the command starts or
/// which repository it reads. Two kinds of setting cannot. One switches a
/// program off: `core.fsmonitor=false` starts no monitor, `core.pager=cat`
/// and `pager.<command>=false` start no pager, an empty `credential.helper`
/// clears the helper list, and a hooks path that holds no hooks runs none.
/// The other names no program to begin with: a colour mode, an abbreviation
/// length, the path-quoting switch and the wire protocol version all change
/// how Git prints or negotiates, never what it executes, and none of them
/// moves the worktree or the object store.
///
/// Everything else is held. A setting this does not model may name a program
/// (`diff.external`, `gpg.program`, a filter driver), may turn a verification
/// on that runs one (`log.showSignature`), or may point Git at another
/// checkout (`core.worktree`, `include.path`), and the proof taken over the
/// words after it would not be a proof of what runs.
pub(super) fn inline_setting_is_inert(
    key: &str,
    value: &str,
    inspection: bool,
    context: crate::pretool::PathContext<'_>,
    arguments: &[String],
) -> bool {
    let key = key.to_ascii_lowercase();
    let lowered = value.to_ascii_lowercase();
    let disabled = matches!(lowered.as_str(), "false" | "0" | "no" | "off");
    let boolean = disabled || matches!(lowered.as_str(), "true" | "1" | "yes" | "on");
    // Git drops the pager on an exact `cat`: `git_pager()` compares with
    // `strcmp`, so `CAT` is a program name and keeps its review.
    let paging_off = value.is_empty() || value == "cat";
    match key.as_str() {
        "core.fsmonitor" => disabled,
        "core.hookspath" => inspection && hooks_path_names_no_hooks(value, context.cwd, arguments),
        "core.quotepath" => boolean,
        "core.pager" => paging_off,
        "core.abbrev" => {
            lowered == "auto"
                || (!lowered.is_empty() && lowered.chars().all(|c| c.is_ascii_digit()))
        }
        "credential.helper" => value.is_empty(),
        "protocol.version" => matches!(lowered.as_str(), "0" | "1" | "2"),
        _ if key.starts_with("pager.") => disabled || paging_off,
        // A colour setting chooses a mode or a colour. Holding it to the
        // modes keeps the common machine-readable spelling working without
        // taking a view on what a colour string may hold.
        _ if key.starts_with("color.") => {
            boolean || matches!(lowered.as_str(), "auto" | "always" | "never")
        }
        _ => false,
    }
}
