//! Reads and searches of paths spelled with a bracket class that matches
//! nothing.
//!
//! Framework routes are written with brackets: `app/blog/[slug]/page.tsx` is
//! one file of a Next.js application. When the class matches no entry the
//! shell hands the program the word as it was typed, so the word names the
//! literal path and is screened exactly as the same path without brackets
//! would be. Proving the class is inert is this module's job; the screens
//! themselves stay in [`super`] and in `read_paths`.
use super::ReadContext;

/// A recursive `ls` operand that the shell passes through literally. Only
/// bracket characters may differ from an ordinary bounded target.
pub(in crate::pretool) fn safe_literal_bracket_tree(
    value: &str,
    context: ReadContext<'_>,
    recursive: bool,
) -> bool {
    let Some(root) = super::checked_directory(value, context) else {
        return false;
    };
    !recursive || super::walk(root, &[], &[], false, false)
}

/// A content search of a path whose bracket class matches nothing.
///
/// Framework routes are spelled with brackets: `app/blog/[slug]/page.tsx` is
/// one file in a Next.js application, and `rg -n useRouter app/[locale]` is
/// an ordinary search of one directory. The shell finds nothing for the class
/// and hands `rg` the word as typed, so what is searched is the path spelled
/// out, and it is screened exactly as the same path without brackets would
/// be: the whole tree below it is walked, and an Oh My Pi agent-state tree is
/// refused as for a literal search root.
pub(in crate::pretool) fn safe_literal_bracket_search_target(
    value: &str,
    context: ReadContext<'_>,
) -> bool {
    inert_bracket_class(value, context) && literal_bracket_walk(value, context)
}

/// A content read of a file whose bracket class matches nothing.
///
/// `head -50 app/blog/[slug]/page.tsx` names one file of a Next.js route, and
/// `sed -n 1,40p app/[locale]/layout.tsx` another. The class matches nothing
/// on disk, so the shell hands the program the word as it was typed, and the
/// file it names is screened exactly as the same path without brackets would
/// be: it has to resolve to a regular file this crate may read.
pub(in crate::pretool) fn safe_literal_bracket_read_target(
    value: &str,
    context: ReadContext<'_>,
) -> bool {
    inert_bracket_class(value, context)
        && crate::pretool::read_paths::bounded_literal_bracket_target(
            value,
            context.home_dir,
            context.cwd,
            false,
        )
}

/// Whether a bracket class in a shell word cannot match anything, so the word
/// reaches the program as it was typed. The class has to match nothing under
/// both matchers: the default one, which reads it byte by byte, and the
/// folded one, since under `nocaseglob` `app/[slug]` would expand to a
/// directory named `S` rather than reach the literal route. A class holding a
/// range is left to review, because the shell expands the range in the
/// locale's collating sequence, which neither matcher models.
pub(super) fn inert_bracket_class(value: &str, context: ReadContext<'_>) -> bool {
    value.contains('[')
        && !value.contains(['*', '?', '!'])
        && !super::super::glob_class::bracket_fallback_unsafe(value)
        && super::glob_expand::expand_glob_matches(value, context)
            .is_some_and(|matches| matches.is_empty())
        && super::glob_expand::expand_glob_matches_folded(value, context)
            .is_some_and(|matches| matches.is_empty())
}

fn literal_bracket_walk(value: &str, context: ReadContext<'_>) -> bool {
    if super::parent_component(value)
        || !crate::pretool::read_paths::bounded_literal_bracket_target(
            value,
            context.home_dir,
            context.cwd,
            true,
        )
    {
        return false;
    }
    let Some(root) = super::expanded_operand(value, context) else {
        return false;
    };
    !super::inside_agent_state(&root, context) && super::walk(root, &[], &[], false, false)
}
