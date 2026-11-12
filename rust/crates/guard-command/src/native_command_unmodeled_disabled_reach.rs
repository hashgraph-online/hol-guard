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
//! disabled extension's programs are unknown or named anywhere in the text.

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
            let program = program
                .strip_suffix(".exe")
                .or_else(|| program.strip_suffix(".cmd"))
                .unwrap_or(&program);
            segment.path_overridden
                || !segment.wrapper_chain.is_empty()
                || program.is_empty()
                || program.contains(['$', '`', '/', '\\', '*', '?', '['])
                || INTERPRETERS.contains(&program)
        });
        if opaque_segment {
            return true;
        }
        let named = named_words(&command.normalized_text);
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
