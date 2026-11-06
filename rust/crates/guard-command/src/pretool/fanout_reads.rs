//! Read-only `find` fan-out: `find ROOT -type f -name '*.ext' -exec CHILD {} +`
//! and `find ROOT -type f -name '*.ext' -print0 | xargs -0 CHILD`.
//!
//! The child receives file names nobody can see in advance, so admission rests
//! on the producer and on the child's own read-only proof:
//!
//! - every root resolves inside the verified workspace (relative, or the
//!   workspace's own absolute spelling), is not the home directory or one of
//!   its ancestors, and passes the same bounded read-target proof as
//!   `cat src/a.js`;
//! - the expression is flat and has `-type f`. Under find's default `-P` a
//!   symlink has type `l`, so a workspace symlink to a secret is never listed,
//!   and `-L`, `-H` and `-follow` are not part of the shape;
//! - a child that reads file contents needs a `-name '*.ext'` test with a
//!   source or documentation extension, so `.env`, `.env.local`, `.npmrc`
//!   and key files are not reachable by a broad `find`;
//! - the child must pass its existing exact-safe proof with one file operand
//!   appended, which is what keeps writes, network and execution out;
//! - `xargs` needs `-0` after `-print0`: whitespace splitting lets a crafted
//!   directory name such as `x /abs/secret` add a second path. Without `-r`
//!   an empty result still runs the child with no operand, so only a child
//!   that stays bounded then (not `rg` or a recursive `grep`) may omit it.
//!
//! `xargs -I`, `sh -c`, `-delete`, `-fprint`, `-ok` and non-`find` producers
//! never reach this module; the parser leaves them uncertain.

use super::safe_reads::{bounded_read_target, verified_path_context};
use super::segment_proof::exact_safe_segment_with_context;
use super::PathContext;
use crate::read_only_fanout::{self as fanout, source_extension, FindShape};
use crate::{CanonicalCommandV1, CommandSegmentV1};

fn plain_extension_pattern(pattern: &str) -> bool {
    pattern.strip_prefix("*.").is_some_and(source_extension)
}

fn contained_roots(shape: &FindShape<'_>, context: PathContext<'_>) -> bool {
    roots_contained(shape.roots, context)
}

fn roots_contained<R: AsRef<str>>(roots: &[R], context: PathContext<'_>) -> bool {
    let (Some(home), Some(cwd)) = (context.home_dir, context.cwd) else {
        return false;
    };
    if !verified_path_context(Some(home), Some(cwd))
        || !std::path::Path::new(cwd).is_absolute()
        || !std::path::Path::new(home).is_absolute()
    {
        return false;
    }
    let (Ok(workspace), Ok(home_root)) = (std::fs::canonicalize(cwd), std::fs::canonicalize(home))
    else {
        return false;
    };
    // A session in the home directory, or above it, has no workspace boundary.
    if home_root.starts_with(&workspace) {
        return false;
    }
    // A root spelled with the workspace's own absolute path names the same
    // directory as the relative spelling. Where it resolves, links and `..`
    // included, is what decides, so an absolute root has to land inside the
    // workspace as well.
    roots.iter().all(|root| {
        let root = root.as_ref();
        !root.starts_with(['\\', '~'])
            && bounded_read_target(root, Some(home), Some(cwd), true)
            && std::fs::canonicalize(std::path::Path::new(cwd).join(root))
                .is_ok_and(|resolved| resolved.starts_with(&workspace))
    })
}

fn producer_allowed(shape: &FindShape<'_>, child: &[String], context: PathContext<'_>) -> bool {
    shape.regular_files_only
        && (!fanout::child_reads_contents(child)
            || shape
                .patterns
                .iter()
                .any(|pattern| plain_extension_pattern(pattern)))
        && contained_roots(shape, context)
}

/// The child as it will run, with one stand-in file operand last.
fn child_proven(
    model: &CanonicalCommandV1,
    segment: &CommandSegmentV1,
    child: &[String],
    context: PathContext<'_>,
) -> bool {
    child_proven_with(
        model,
        segment,
        child,
        Some(fanout::PLACEHOLDER),
        false,
        context,
    )
}

fn child_proven_with(
    model: &CanonicalCommandV1,
    segment: &CommandSegmentV1,
    child: &[String],
    operand: Option<&str>,
    allow_git_helper_context: bool,
    context: PathContext<'_>,
) -> bool {
    child.first().is_some_and(|_| {
        let proxy = child_segment(segment, child, operand);
        exact_safe_segment_with_context(model, &proxy, allow_git_helper_context, context)
    })
}

/// The command a launcher runs: its child with one operand appended.
fn child_segment(
    segment: &CommandSegmentV1,
    child: &[String],
    operand: Option<&str>,
) -> CommandSegmentV1 {
    let mut tokens = child.to_vec();
    tokens.extend(operand.map(str::to_owned));
    CommandSegmentV1 {
        text: tokens.join(" "),
        executable: tokens.first().cloned(),
        arguments: tokens[1..].to_vec(),
        tokens,
        environment_names: Vec::new(),
        wrapper_chain: Vec::new(),
        path_overridden: false,
        execution_context: segment.execution_context.clone(),
        pipeline_index: 0,
        span: segment.span.clone(),
    }
}

fn plain(segment: &CommandSegmentV1) -> bool {
    segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
}

/// Whether the shell hands the segment the words this proof reads.
///
/// The shape and the child are read as the words they are written as, but
/// brace expansion runs first: `find . -type f -name {x,-delete} -exec cat {}
/// +` is read here as one pattern and a `cat` child, while `find` receives a
/// `-delete` action of its own. A segment whose words the shell would split,
/// or whose expansion this reader does not follow, keeps review.
fn words_as_written(segment: &CommandSegmentV1) -> bool {
    segment
        .arguments
        .iter()
        .all(|argument| super::brace_words::stays_one_word(argument))
}

/// `find ... -exec CHILD {} +` with a proven producer scope and child.
pub(super) fn safe_find_exec(
    model: &CanonicalCommandV1,
    segment: &CommandSegmentV1,
    context: PathContext<'_>,
) -> bool {
    plain(segment)
        && words_as_written(segment)
        && fanout::find_exec(&segment.arguments).is_some_and(|exec| {
            producer_allowed(&exec.shape, exec.child, context)
                && child_proven(model, segment, exec.child, context)
        })
}

/// `fd ... -x CHILD` with a proven producer scope and child.
///
/// fd appends the file name to the child, so the command that runs is the
/// child as written with one operand last -- the same proxy the `find -exec`
/// proof judges. `--type f` carries the regular-file bound find spells
/// `-type f`, and `--extension` carries the name bound find spells
/// `-name '*.ext'`.
pub(super) fn safe_fd_exec(
    model: &CanonicalCommandV1,
    segment: &CommandSegmentV1,
    context: PathContext<'_>,
) -> bool {
    plain(segment)
        && words_as_written(segment)
        && fanout::fd::fd_exec(&segment.arguments).is_some_and(|exec| {
            fanout::fd::producer_shape_proven(&exec)
                && roots_contained(&exec.shape.roots, context)
                && child_proven(model, segment, exec.child, context)
        })
}

fn previous_find<'a>(
    model: &'a CanonicalCommandV1,
    segment: &CommandSegmentV1,
) -> Option<&'a CommandSegmentV1> {
    let index = model
        .segments
        .iter()
        .position(|candidate| candidate.span.start == segment.span.start)?;
    let previous = &model.segments[index.checked_sub(1)?];
    fanout::xargs_follows_find(
        previous,
        segment.pipeline_index,
        &segment.execution_context,
        &segment.arguments,
    )
    .then_some(previous)
}

/// `find ... -print0 | xargs -0 CHILD` with a proven producer scope and child.
pub(super) fn safe_xargs(
    model: &CanonicalCommandV1,
    segment: &CommandSegmentV1,
    context: PathContext<'_>,
) -> bool {
    let (true, Some(previous), Some(xargs)) = (
        plain(segment) && words_as_written(segment),
        previous_find(model, segment),
        fanout::xargs(&segment.arguments),
    ) else {
        return false;
    };
    let Some(shape) = fanout::find_shape(&previous.arguments) else {
        return false;
    };
    if !words_as_written(previous) {
        return false;
    }
    xargs.null_separated
        && (xargs.no_run_if_empty || fanout::bounded_without_operands(xargs.child))
        && shape.print0
        && producer_allowed(&shape, xargs.child, context)
        && child_proven(model, segment, xargs.child, context)
}

/// `rg -l --null PATTERN ROOT | xargs -0 CHILD` with a contained root and a
/// proven child.
///
/// The search prints the paths of the files it matched, each one beginning
/// with a root this proof resolved inside the workspace, so the child receives
/// names from the same walk `find` would have produced. NUL separation is
/// required on both halves: a name holding a space would otherwise reach the
/// child as words that were never proven.
///
/// A child that reads file contents asks for the same extension bound a `find`
/// producer asks for, through `-g` or `--include`, because a listing search
/// walks every file under its root whatever its name. Every glob on the line
/// has to carry it: the search prints a file that matched any one of them, so
/// a single `-g '*.env*'` beside `-g '*.ts'` widens the walk rather than
/// narrowing it.
pub(super) fn safe_listing_xargs(
    model: &CanonicalCommandV1,
    segment: &CommandSegmentV1,
    context: PathContext<'_>,
) -> bool {
    let (true, Some(previous), Some(xargs)) = (
        plain(segment) && words_as_written(segment),
        previous_listing(model, segment),
        fanout::xargs(&segment.arguments),
    ) else {
        return false;
    };
    let Some(shape) = previous
        .executable
        .as_deref()
        .map(crate::parser_executables::executable_basename)
        .and_then(|tool| fanout::listing::shape(tool, &previous.arguments))
    else {
        return false;
    };
    if !words_as_written(previous) {
        return false;
    }
    xargs.null_separated
        && shape.null_separated
        && (xargs.no_run_if_empty || fanout::bounded_without_operands(xargs.child))
        && (!fanout::child_reads_contents(xargs.child)
            || (!shape.patterns.is_empty()
                && shape
                    .patterns
                    .iter()
                    .all(|pattern| plain_extension_pattern(pattern))))
        && roots_contained(&shape.roots, context)
        && child_proven(model, segment, xargs.child, context)
}

fn previous_listing<'a>(
    model: &'a CanonicalCommandV1,
    segment: &CommandSegmentV1,
) -> Option<&'a CommandSegmentV1> {
    let index = model
        .segments
        .iter()
        .position(|candidate| candidate.span.start == segment.span.start)?;
    let previous = &model.segments[index.checked_sub(1)?];
    fanout::listing::xargs_follows(
        previous,
        segment.pipeline_index,
        &segment.execution_context,
        &segment.arguments,
    )
    .then_some(previous)
}

/// `git merge-base REV... | xargs git ...` whose child passes the Git read
/// proof with an object name appended. `merge-base` prints only object names,
/// so that is all the child can receive; with no input and no `-r`, the child
/// runs without the operand, which the same read proof also covers.
///
/// Like a direct Git read, the child defers its helper check to the Git
/// configuration probe, which sees it through [`git_xargs_child`].
pub(super) fn safe_git_xargs(
    model: &CanonicalCommandV1,
    segment: &CommandSegmentV1,
    context: PathContext<'_>,
) -> bool {
    let Some(xargs) = fanout::xargs_git(&segment.arguments) else {
        return false;
    };
    let follows = model
        .segments
        .iter()
        .position(|candidate| candidate.span.start == segment.span.start)
        .is_some_and(|index| follows_object_names(model, index));
    follows
        && plain(segment)
        && words_as_written(segment)
        && child_proven_with(
            model,
            segment,
            xargs.child,
            Some(fanout::OBJECT_NAME_PLACEHOLDER),
            true,
            context,
        )
        && (xargs.no_run_if_empty
            || child_proven_with(model, segment, xargs.child, None, true, context))
}

fn follows_object_names(model: &CanonicalCommandV1, index: usize) -> bool {
    let segment = &model.segments[index];
    index.checked_sub(1).is_some_and(|previous| {
        fanout::xargs_follows_object_names(
            &model.segments[previous],
            segment.pipeline_index,
            &segment.execution_context,
            &segment.arguments,
        )
    })
}

/// The Git read the `xargs` stage at `index` runs for `git merge-base REV... |
/// xargs git ...`, with an object name appended, so the configuration probe
/// and the read floor judge it as they judge a direct Git read.
pub(super) fn git_xargs_child(
    model: &CanonicalCommandV1,
    index: usize,
) -> Option<CommandSegmentV1> {
    let segment = model.segments.get(index)?;
    let is_xargs = segment
        .executable
        .as_deref()
        .is_some_and(|name| name == "xargs");
    let xargs = fanout::xargs_git(&segment.arguments).filter(|_| is_xargs)?;
    (plain(segment) && follows_object_names(model, index))
        .then(|| child_segment(segment, xargs.child, Some(fanout::OBJECT_NAME_PLACEHOLDER)))
}

/// Guidance for a `find | xargs` that splits names on whitespace.
pub(super) fn whitespace_split_reason(model: &CanonicalCommandV1) -> Option<String> {
    model
        .segments
        .iter()
        .any(|segment| {
            segment
                .executable
                .as_deref()
                .is_some_and(|name| super::executable_basename(name) == "xargs")
                && previous_find(model, segment).is_some()
                && fanout::xargs(&segment.arguments).is_some_and(|xargs| !xargs.null_separated)
        })
        .then(|| {
            "HOL Guard requires review because xargs splits file names on whitespace, so a crafted directory name can add another path. Use find DIR -type f -name '*.ext' -exec cat {} +, or find ... -print0 | xargs -0 cat, which Guard can prove read-only."
                .to_owned()
        })
}
