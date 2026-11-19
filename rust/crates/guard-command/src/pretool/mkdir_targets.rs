//! `mkdir` with several targets: `mkdir -p /tmp/run/logs /tmp/run/out`.
//!
//! `mkdir` only creates real directories. It never opens, overwrites or
//! removes a path, and a directory it makes cannot redirect a later target
//! the way a link could. So several targets need no wider trust than one:
//! each target must clear the screen a lone target clears, and one target
//! that fails keeps the whole command in review.

/// The most targets one `mkdir` may name and still be proven.
const MAX_TARGETS: usize = 16;

/// `mkdir [-p|--parents] [--] TARGET...`, where every target passes on its
/// own. A word after the options that starts with `-` is refused, so an
/// option can never hide behind a target. Only `-p` admits a nested new
/// path below a private temporary directory, as it does for one target.
pub(super) fn mkdir_arguments(
    arguments: &[String],
    context: super::super::PathContext<'_>,
) -> bool {
    let (parents, rest) = match arguments.split_first() {
        Some((flag, rest)) if matches!(flag.as_str(), "-p" | "--parents") => (true, rest),
        _ => (false, arguments),
    };
    let targets = match rest.split_first() {
        Some((separator, rest)) if separator == "--" => rest,
        _ => rest,
    };
    (1..=MAX_TARGETS).contains(&targets.len())
        && targets.iter().all(|target| {
            !target.starts_with('-')
                && (super::creatable_target(target, context, true)
                    || (parents
                        && super::temporary_directories::nested_temporary_directory(
                            target, context,
                        )))
        })
}
