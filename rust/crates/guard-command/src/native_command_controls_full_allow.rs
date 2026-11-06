//! Coverage for an extension the user turned on in full.

use std::collections::BTreeSet;

use crate::CanonicalCommandV1;

impl super::CompiledNativeCommandControls {
    /// Segments whose program belongs to an extension the user turned on in
    /// full.
    ///
    /// A rule names a shape Guard already models, so a program the extension
    /// watches that no rule claims -- `git ls-remote`, `git archive`, a verb
    /// a later Git release adds -- carries no observation at all, and nothing
    /// can cover it. An Allow that reaches only the modelled spellings stops
    /// the ones beside them, which is what users report as "I allowed git and
    /// it still asks". Reading the whole extension as covering the programs
    /// it watches answers for those variations too.
    ///
    /// Only an extension whose every declared permission the user explicitly
    /// enabled counts, so a partial Allow still covers exactly its own rules.
    ///
    /// A segment is covered only when
    /// [`crate::command_compatibility::segment_settles_uncertainty`] answers
    /// for it, which is the same per-program contract the uncertainty path
    /// already uses to decide what an Allow may settle. For Git that means a
    /// builtin subcommand this release models, no setting or environment name
    /// that makes Git run a configured program, and a verified repository
    /// route; a wrapper chain, an alias, an unknown verb, `git credential`
    /// and `git filter-branch` all stay outside it. Reading the extension's
    /// watched names alone would cover any argv whose program happened to be
    /// named `git`.
    ///
    /// The walk also stops at the first step that is neither proven benign
    /// nor a Git step that rewrites no tracked file, because a checkout or
    /// reset can replace the program, configuration or bind-mounted file a
    /// later step runs; segments after such a step keep the review they had.
    ///
    /// A step that points its own output at a file it names is left out of the
    /// coverage as well as ending the walk. `git log --output=.git/config`
    /// reads a verb the extension models, but what it does is write, and an
    /// answer about Git's reads never covers that.
    ///
    /// This widens coverage, not the floors around it: `fixed_command_floor`,
    /// `protected_checkout_destination`, the caller's bounded and
    /// sensitive-target checks and every floor Rust raises after the controls
    /// run all keep their answer.
    pub(super) fn fully_allowed_extension_segments(
        &self,
        command: &CanonicalCommandV1,
        benign: &BTreeSet<usize>,
        context: crate::pretool::PathContext<'_>,
    ) -> BTreeSet<usize> {
        let watched: BTreeSet<String> = self
            .program
            .extensions
            .iter()
            .enumerate()
            .filter(|(_, extension)| self.allowed_in_full(extension))
            .flat_map(|(index, extension)| {
                self.program.extension_known_names(
                    index,
                    super::unmodeled::compatibility_executables(&extension.extension_id),
                )
            })
            .collect();
        if watched.is_empty() {
            return BTreeSet::new();
        }
        let mut covered = BTreeSet::new();
        for (index, segment) in command.segments.iter().enumerate() {
            let watches_this_segment = watched
                .contains(&crate::command_compatibility::basename(segment))
                && !crate::pretool::git_step_names_an_output_file(segment)
                && crate::command_compatibility::segment_settles_uncertainty(segment, context);
            if watches_this_segment {
                covered.insert(index);
            }
            if !benign.contains(&index) && !crate::pretool::step_preserves_later_programs(segment) {
                break;
            }
        }
        covered
    }

    /// Whether the user explicitly enabled every permission `extension`
    /// declares that they can turn on, with none of them blocked and the
    /// extension itself active. An extension that declares no such permission
    /// is left out rather than read as allowed by default.
    ///
    /// An extension that delegates its protection to the package firewall is
    /// left out entirely. Its one permission names who owns the decision, not
    /// consent to run whatever code an install or a task script fetches, so
    /// turning it on never covers `npm`, `pip`, `cargo` or their siblings.
    ///
    /// A permission the user cannot configure is not read as missing consent,
    /// because no answer of theirs could supply it. Its protection is kept
    /// elsewhere: a segment that matches its rule carries an observation
    /// whose permission is not explicitly enabled, and the caller refuses the
    /// whole command before this coverage is added.
    fn allowed_in_full(&self, extension: &crate::native_command_program::ProgramExtension) -> bool {
        let mut configurable = extension
            .permissions
            .iter()
            .filter(|permission| permission.configurable)
            .peekable();
        configurable.peek().is_some()
            && extension.delegated_protection.is_none()
            && self.active_extensions.contains(&extension.extension_id)
            && !self.blocked_extensions.contains(&extension.extension_id)
            && configurable.all(|permission| {
                self.explicitly_enabled_permissions
                    .contains(&permission.permission_id)
                    && !self.blocked_permissions.contains(&permission.permission_id)
            })
    }
}
