//! Shell `grep --include` scope proofs: which files the globs select below a
//! directory operand, and whether any of them is sensitive.

use super::verified_directory_root;
use crate::pretool::search_scope_filter::SearchFilter;
use crate::pretool::search_scope_walk::{include_scope_proven, walk_scope, Ignores};
use std::path::Path;

/// Shell `grep` with `--include` globs the name screen cannot clear, such as
/// `*.md` or `*.rs`: true when below each directory root no sensitive file
/// matches one of them.
///
/// An include narrows what `grep` opens and can never widen it: `grep` reads
/// no ignore file and walks hidden entries already, so there is nothing for a
/// glob to re-include. The walk therefore counts every reachable entry.
///
/// A glob holding a separator is left unproven. `grep` matches such a glob
/// against the whole name it reached the file by, which depends on how the
/// operand was spelled, and this walk renders no such path.
pub(in crate::pretool) fn grep_include_scope_proven(
    roots: &[&str],
    globs: &[&str],
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    roots.iter().all(
        |target| match verified_directory_root(target, home_dir, cwd) {
            Some(root) => include_filter(globs, target).is_some_and(|filter| {
                // The filter is built from `globs` alone, so they and the root
                // and home decide the walk.
                crate::pretool::search::memoized_keyed(
                    format!("include\0{root:?}\0{}\0{home_dir:?}", globs.join("\0")),
                    || directory_include_proven(&root, &filter, home_dir),
                )
            }),
            // A root that is a regular file was screened as a path already,
            // and an include can only keep `grep` from opening it.
            None => cwd.is_some_and(|cwd| {
                std::fs::symlink_metadata(Path::new(cwd).join(target))
                    .is_ok_and(|metadata| metadata.is_file())
            }),
        },
    )
}

/// True when the files `globs` select below `root` hold nothing sensitive.
///
/// The recursive walk reads whatever it reaches, so a secret anywhere below
/// the root refuses it. With an include the search opens only the files the
/// globs name, and this proof walks the tree under exactly that filter: a
/// directory is still descended, but a file no glob selects is not read and
/// so cannot be printed. The root must be a directory, because the caller
/// asks this only for a recursive operand.
///
/// Every other reading of the same search answers first and walks the tree to
/// do it, so this one walks under the smaller include budget: a tree too
/// large for it stays unproven and the search keeps the answer those readings
/// reached.
pub(in crate::pretool) fn grep_include_walk_proven(
    root: &str,
    globs: &[&str],
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let Some(filter) = include_filter(globs, root) else {
        return false;
    };
    verified_directory_root(root, home_dir, cwd).is_some_and(|directory| {
        !crate::pretool::read_paths::inside_agent_state_tree(&directory, home_dir)
            && include_scope_proven(&directory, globs, &filter, home_dir)
    })
}

/// The walk filter for a grep include, or nothing when the globs reach past
/// what it models. A separator makes the glob match against a base this walk
/// does not model, and the implementations differ on what it is.
///
/// Braces are refused because the filter below expands them the way ripgrep
/// does, while both greps match the glob through `fnmatch`, which carries no
/// brace expansion and reads `{` and `}` as the bytes they are. The expansion
/// would stand for a set of names the search never selects, and miss the one
/// name -- the literal spelling -- that it does.
fn include_filter(globs: &[&str], operand: &str) -> Option<SearchFilter> {
    if globs.iter().any(|glob| {
        glob.contains(['/', '\\', '{', '}'])
            || !(matches_only_a_name(glob) || misses_every_rendered_path(glob, operand))
    }) {
        return None;
    }
    SearchFilter::from_rg_inclusions(globs)
}

/// Whether a `--include` glob selects the same files under both `grep`
/// implementations this walk has to answer for.
///
/// GNU grep matches the glob against an entry's name. BSD grep, which is the
/// `grep` macOS ships, matches the name and the whole path it reached the
/// file by, through an `fnmatch` without `FNM_PATHNAME`: a wildcard crosses a
/// separator there, so `--include 'deploy*'` over a `deploy` directory
/// selects `deploy/secrets/id_rsa`, which no name match selects. This walk
/// renders names, not the path the operand spelled.
///
/// Two shapes answer alike under both. A literal name matches no path that
/// holds a separator, and `*` followed by a literal matches a path only when
/// its last component matches too, because the literal carries no separator
/// of its own. Every other wildcard placement needs
/// [`misses_every_rendered_path`] to rule the path match out.
fn matches_only_a_name(glob: &str) -> bool {
    !glob.strip_prefix('*').unwrap_or(glob).contains('*')
}

/// Whether `glob` can match none of the paths `grep` renders below `operand`.
///
/// Every such path starts with the operand as the command spelled it and a
/// separator. A glob that carries no separator of its own and whose literal
/// head disagrees with that prefix matches no path, however its wildcards
/// fall, so only the name match is left and both greps answer alike. This is
/// what keeps `--include 'README*' docs` and `--include '.env.*' tests`
/// readable while `--include 'deploy*' deploy`, where the head does agree,
/// stays unmodeled.
fn misses_every_rendered_path(glob: &str, operand: &str) -> bool {
    let prefix = format!("{}/", operand.trim_end_matches('/'));
    let mut rendered = prefix.chars();
    for character in glob.chars() {
        if matches!(character, '*' | '?' | '[') {
            return false;
        }
        match rendered.next() {
            Some(expected) if expected == character => {}
            // The literal head leaves the prefix behind, so no path below
            // this operand begins the way the glob demands.
            _ => return true,
        }
    }
    // The glob ran out inside the prefix: every rendered path is longer than
    // what it can match.
    true
}

fn directory_include_proven(root: &Path, filter: &SearchFilter, home_dir: Option<&str>) -> bool {
    #[cfg(test)]
    crate::pretool::search::count_walk("include-scope", root);
    !crate::pretool::read_paths::inside_agent_state_tree(root, home_dir)
        && walk_scope(root, filter, Ignores::None, false, home_dir, &mut None).is_ok()
}
