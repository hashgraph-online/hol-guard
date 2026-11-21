//! Where a routed Git step runs: the working directory folded through its
//! leading `-C` routes, and those routes as a probe must replay them.

use crate::CommandSegmentV1;

/// The directory the later read runs Git in: the segment's working directory
/// folded through its leading `-C` routes, as Git folds them. `None` when a
/// leading option could send the read somewhere this cannot name, which
/// `--git-dir` and `--work-tree` do.
pub(super) fn read_route(
    later: &CommandSegmentV1,
    context: super::super::PathContext<'_>,
) -> Option<std::path::PathBuf> {
    let mut route = std::path::PathBuf::from(context.cwd?);
    let mut arguments = later.arguments.iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-P" | "--no-pager" | "--no-optional-locks" | "--literal-pathspecs" => {}
            // A relative path joins what came before it; an absolute one
            // replaces it, which `PathBuf::push` already does.
            "-C" => route.push(arguments.next()?),
            "-c" => {
                arguments.next()?;
            }
            _ if argument.starts_with('-') => return None,
            // The subcommand: every later word is its own.
            _ => break,
        }
    }
    std::fs::canonicalize(route).ok()
}

/// The leading `-C <dir>` pairs of a Git segment, in order, as the segment
/// spells them, so a probe folds them against the same working directory Git
/// does. Options that only shape output are dropped; [`read_route`] has
/// already refused any leading option that moves the repository.
pub(super) fn leading_routes(arguments: &[String]) -> Vec<String> {
    let mut routes = Vec::new();
    let mut words = arguments.iter();
    while let Some(argument) = words.next() {
        match argument.as_str() {
            "-C" => match words.next() {
                Some(directory) => {
                    routes.push(argument.clone());
                    routes.push(directory.clone());
                }
                None => break,
            },
            "-c" => {
                words.next();
            }
            _ if argument.starts_with('-') => {}
            _ => break,
        }
    }
    routes
}
