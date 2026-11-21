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

/// A plain `ls` operand whose bracket class matches nothing, as in
/// `ls ~/work/app/api/groups/\[slug\]/`. The shell hands `ls` the word as
/// typed, so it lists that one route directory, and the path is screened as
/// a read of a route file is, with a directory admitted. The shell expands
/// `~` from its own HOME, so a home spelling needs that HOME to be the
/// declared one. A quoted `~` stays literal and names `./~`, so it also needs
/// the working directory to hold no `~` entry.
pub(in crate::pretool) fn safe_literal_bracket_listing_target(
    value: &str,
    context: ReadContext<'_>,
) -> bool {
    (!value.starts_with('~')
        || context.shell_home_matches
            && super::expanded_operand("./~", context).is_some_and(|path| {
                std::fs::symlink_metadata(path)
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            }))
        && inert_bracket_class(value, context)
        && crate::pretool::read_paths::bounded_literal_bracket_target(
            value,
            context.home_dir,
            context.cwd,
            true,
        )
}

/// A listing operand whose pattern characters may have been escaped, as in
/// `ls trap/\[k\]`. Without a quote map the screen cannot tell that word from
/// `trap/[k]`, so it screened what the pattern matches, `trap/k`, while the
/// shell lists the literal `trap/[k]`. A literal entry spelled that way must
/// therefore clear the read screen on its own, and a walk of one is refused.
/// A word whose quoting is known, or that names nothing literally, needs no
/// second proof.
pub(in crate::pretool) fn listable_spelling(
    value: &str,
    context: ReadContext<'_>,
    recursive: bool,
    quoting_known: bool,
) -> bool {
    if quoting_known || !value.contains(['*', '?', '[']) {
        return true;
    }
    let Some(path) = super::expanded_operand(value, context) else {
        return false;
    };
    match std::fs::symlink_metadata(path) {
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        Ok(_) => {
            !recursive
                && crate::pretool::read_paths::bounded_literal_bracket_target(
                    value,
                    context.home_dir,
                    context.cwd,
                    true,
                )
        }
    }
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
pub(in crate::pretool) fn inert_bracket_class(value: &str, context: ReadContext<'_>) -> bool {
    value.contains('[')
        && !value.contains(['*', '?', '!'])
        && !super::super::glob_class::bracket_fallback_unsafe(value)
        && (quoted_word(value, context)
            || (super::glob_expand::expand_glob_matches(value, context)
                .is_some_and(|matches| matches.is_empty())
                && super::glob_expand::expand_glob_matches_folded(value, context)
                    .is_some_and(|matches| matches.is_empty())))
}

/// Whether the shell hands `value` over exactly as typed because every
/// bracket in it sat inside quotes. No shell globs a quoted word, so
/// `"app/(group)/blog/[slug]/page.tsx"` names that route file even though
/// the expansion matchers refuse the parentheses, which zsh would read as a
/// pattern group in an unquoted word. A word starting with `~` is left to
/// the expansion proof: quoted, the tilde is not expanded, so the word names
/// a directory called `~` rather than the home path the screens resolve.
fn quoted_word(value: &str, context: ReadContext<'_>) -> bool {
    !value.starts_with('~') && context.literal_words.iter().any(|word| word == value)
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

/// A search operand whose brackets may have been escaped, as in
/// `grep -rn foo trap/\[k\]`. The shell removes the backslashes before the
/// screen sees the word, so it reads like the pattern `trap/[k]`, and a proof
/// of what that pattern matches (`trap/k`) says nothing about the entry the
/// program searches, the literal `trap/[k]`. When an entry of that literal
/// name exists it has to clear the search screen on its own, followed
/// through any link to where it leads.
pub(super) fn literal_spelling_searchable(value: &str, context: ReadContext<'_>) -> bool {
    if !value.contains('[') {
        return true;
    }
    let Some(path) = super::expanded_operand(value, context) else {
        return false;
    };
    match std::fs::symlink_metadata(path) {
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        Ok(_) => literal_bracket_walk(value, context),
    }
}
