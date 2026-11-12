//! Whether a disabled extension could own a command whose check timed out.
//!
//! A check that runs out of time settles at a review, so the user can still
//! approve it once the machine is less busy. An administrator disable is a
//! floor the user cannot clear, so the review must not stand in for a check
//! that might have reached a disabled rule. Treating every disable as in
//! reach turned each timeout into a block no approval could clear: one
//! disabled Kubernetes permission blocked `git diff --stat` whenever the
//! machine was slow.
//!
//! A catalog rule matches a segment by the program it runs, so a disabled
//! extension can only reach a command that names one of its programs. The
//! check below keeps the block whenever it cannot show that: the command was
//! not modeled exactly, a segment runs a program by path, through an
//! expansion, a wrapper or an interpreter that runs other text, or a
//! disabled extension's programs are unknown or named anywhere in the text or
//! in the words the parser decoded from it. An MCP tool call is matched by
//! its tool name, not its command, so a disabled extension with an MCP
//! surface is always in reach of one.

use super::{named_words, INTERPRETERS};
use crate::native_command_controls::CompiledNativeCommandControls;
use crate::CanonicalCommandV1;

impl CompiledNativeCommandControls {
    /// `true` unless every administrator disable provably falls outside
    /// `command`. A tool call with no shell command, or one that carries
    /// package names for the delegated firewall, is never bounded here.
    pub(crate) fn disabled_owner_in_reach(
        &self,
        command: Option<&CanonicalCommandV1>,
        tool: Option<&str>,
        packages: &[String],
    ) -> bool {
        if self.blocked_permissions.is_empty() && self.blocked_extensions.is_empty() {
            return false;
        }
        let Some(command) = command else {
            return true;
        };
        if !packages.is_empty()
            || command.confidence != "exact"
            || command.path_overridden
            || !command.wrapper_chain.is_empty()
            || command.segments.is_empty()
        {
            return true;
        }
        let opaque_segment = command.segments.iter().any(|segment| {
            let Some(executable) = segment.executable.as_deref() else {
                return true;
            };
            let program = executable.to_ascii_lowercase();
            let direct_script = [
                ".sh", ".bash", ".zsh", ".fish", ".ps1", ".py", ".rb", ".pl", ".cmd", ".bat",
            ]
            .iter()
            .any(|suffix| program.ends_with(suffix));
            let program = program
                .strip_suffix(".exe")
                .or_else(|| program.strip_suffix(".cmd"))
                .unwrap_or(&program);
            segment.path_overridden
                || !segment.wrapper_chain.is_empty()
                || program.is_empty()
                || direct_script
                || program.contains(['$', '`', '/', '\\', '*', '?', '['])
                || INTERPRETERS.contains(&program)
        });
        if opaque_segment {
            return true;
        }
        // The delegated gate matches an MCP extension by an `mcp__` tool name
        // (or by package, handled above), whatever command the call carries.
        let mcp_tool = tool.is_some_and(|tool| tool.to_ascii_lowercase().starts_with("mcp__"));
        // The parser decodes spellings such as `$'\x6bubectl'`, so the words
        // it read count as well as the text.
        let mut named = named_words(&command.normalized_text);
        for segment in &command.segments {
            for word in segment
                .executable
                .iter()
                .chain(&segment.tokens)
                .chain(&segment.arguments)
            {
                named.extend(named_words(word));
            }
        }
        self.program
            .extensions
            .iter()
            .enumerate()
            .any(|(index, extension)| {
                let disabled = self.blocked_extensions.contains(&extension.extension_id)
                    || extension.permissions.iter().any(|permission| {
                        self.blocked_permissions.contains(&permission.permission_id)
                    });
                if !disabled {
                    return false;
                }
                if !mcp_tool
                    && extension.executables.is_empty()
                    && extension
                        .mcp
                        .as_ref()
                        .is_some_and(|mcp| mcp.mcp_launch.kind == "remote-http")
                {
                    return false;
                }
                if mcp_tool && extension.mcp.is_some() {
                    return true;
                }
                let compatibility = super::compatibility_executables(&extension.extension_id);
                self.program
                    .extension_names(index, compatibility)
                    .is_none_or(|names| names.is_empty() || !names.is_disjoint(&named))
            })
    }
}

#[cfg(test)]
#[path = "native_command_unmodeled_disabled_reach_tests.rs"]
mod tests;
