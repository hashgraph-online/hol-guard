//! The recovery command a bounded-bridge authority block carries.
//!
//! A degraded control floor blocks every tool call, and the block is the only
//! place the person sees it, so the message has to say how to end it. The
//! sentence here is what `zcode_hooks.py` appends, byte for byte.

use std::path::Path;

/// The reason text the native command control floor emits while the local
/// authority is degraded, tampered, or pending recovery.
const AUTHORITY_BLOCK_REASON_MARKER: &str = "native command extension policy";

/// The sentence appended to such a block, in the spelling the bare command
/// takes. [`remediation_for_home`] rewrites the command inside it when the
/// home needs naming.
const AUTHORITY_BLOCK_REMEDIATION: &str = " Run `hol-guard command controls recover-authority` in a terminal to restore the protected control floor.";

/// `zcode_authority_block_reason`, for a block the bridge read out of
/// `guard_home`.
pub(crate) fn zcode_authority_block_reason(reason: &str, guard_home: Option<&Path>) -> String {
    if reason.contains(AUTHORITY_BLOCK_REASON_MARKER)
        && !reason.contains("hol-guard command controls")
    {
        format!("{reason}{}", authority_block_remediation(guard_home))
    } else {
        reason.to_owned()
    }
}

/// The remediation sentence, told which home to repair when that is not the
/// one the command would find on its own.
///
/// The block names the home this bridge read its authority from, and a person
/// who pastes the bare command into a shell pointing somewhere else recovers a
/// different install while this one stays blocked. So the home is named
/// whenever it is not `<home>/.hol-guard`, quoted for the shell it is pasted
/// into, the way [`crate::blocked_request_mode::approval_wait_hint_for_home`]
/// names it on the approval hint. The default home is left out: the short
/// command is the one almost everyone needs, and a path that adds nothing only
/// invites editing.
///
/// `--guard-home` is the flag that names a store and nothing else; `--home`
/// reaches the same store but also moves the home directory, to a directory
/// nobody lives in. It goes on `command`, which is the parser that carries it;
/// after `recover-authority` argparse hands it to the leaf, which takes no
/// options and would reject the whole line.
fn authority_block_remediation(guard_home: Option<&Path>) -> String {
    remediation_for_home(
        guard_home,
        crate::claude_hook_bridge::home_directory().as_deref(),
        cfg!(windows),
    )
}

/// [`authority_block_remediation`] against a given `Path.home()`, so the
/// decision can be read without the process's own environment.
///
/// A home the bridge does not know, and a `Path.home()` the platform will not
/// answer for, both leave the bare command: a runtime that cannot tell the two
/// apart has nothing to add. The homes are compared as they are written. The
/// installer resolves the home it bakes in, so a person whose home is reached
/// through a symlink may be told the path of the install they are already
/// pointing at, which is longer than it needs to be but still the right one.
///
/// A home no shell spelling reaches also keeps the bare command, rather than
/// one the shell would rewrite into a different store; [`quote_home`] says
/// which homes those are.
fn remediation_for_home(
    guard_home: Option<&Path>,
    home_dir: Option<&Path>,
    windows: bool,
) -> String {
    let Some(guard_home) = guard_home else {
        return AUTHORITY_BLOCK_REMEDIATION.to_owned();
    };
    if home_dir.is_none_or(|home| home.join(".hol-guard") == guard_home) {
        return AUTHORITY_BLOCK_REMEDIATION.to_owned();
    }
    let Some(quoted) = quote_home(&guard_home.to_string_lossy(), windows) else {
        return AUTHORITY_BLOCK_REMEDIATION.to_owned();
    };
    AUTHORITY_BLOCK_REMEDIATION.replace(
        "command controls recover-authority",
        &format!("command --guard-home {quoted} controls recover-authority"),
    )
}

/// `home` written the way the shell this block is pasted into reads it, or
/// `None` when no spelling reaches that store.
///
/// POSIX quoting puts `C:\guards\ci` inside single quotes, which `cmd.exe`
/// hands on as part of the path, so a Windows person pastes a command that
/// repairs nothing. A Windows path that needs no quoting is left bare, because
/// quotes a path does not need only invite editing, and one that merely needs
/// holding together is double-quoted, which both shells read literally,
/// backslashes included. A Windows path cannot hold a `"`, so nothing inside
/// has to be escaped.
///
/// Double quotes are not literal to either shell, though. PowerShell expands
/// `$name` inside them and reads a backtick as an escape, and `cmd.exe`
/// expands `%VAR%` and, with delayed expansion, `!name!`. A Windows path may
/// legally hold all four. Single quotes
/// would hold them in PowerShell but become part of the path in `cmd.exe`, so
/// no one rendering reaches such a store. Naming it anyway would send the
/// person to repair a path the shell rewrote while this install stays blocked,
/// which is the failure the naming exists to prevent, so the block keeps the
/// short command instead. `windows` is passed rather than read from `cfg!`, so
/// both renderings are compiled and tested on every platform.
pub(crate) fn quote_home(home: &str, windows: bool) -> Option<String> {
    if !windows {
        return Some(crate::mcp_proxy_shlex::quote(home));
    }
    let plain = !home.is_empty()
        && home.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '_' | '-' | '.' | ':' | '\\' | '/')
        });
    if plain {
        return Some(home.to_owned());
    }
    if home.contains(['$', '%', '`', '!']) {
        return None;
    }
    Some(format!("\"{home}\""))
}

#[cfg(test)]
#[path = "bounded_hook_bridge_remediation_tests.rs"]
mod tests;
