//! A `cd <sibling repository dir> && …` list. Agents step from one checkout
//! into a linked worktree or clone beside it this way. The execution sink
//! peels the same prefix and re-authorizes the remainder with that root as its
//! workspace (`contained_wrapper.py`), so the classifier holds the remainder
//! to the checks it would face from a session started in that root. The sink
//! resolves the root itself and runs nothing when it is gone, so `cd <root>;`
//! cannot fall back to the session directory and is peeled like `&&`. A
//! plain command whose script or tool lies in a sibling repository
//! (`python3 ../other/scripts/report.py`, spelled absolute) runs from that
//! root the same way.
use super::PathContext;
use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::path::{Path, PathBuf};

/// The sibling repository root that confines the run, and the commands to
/// check there: the rest after a `cd <root>` list, or `None` when the whole
/// text runs from the root as issued, `cd` included.
pub(super) fn sibling_run(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> Option<(PathBuf, Option<CanonicalCommandV1>)> {
    match sibling_list(model, context) {
        Some((root, rest)) => Some((root, Some(rest))),
        None => sibling_cd_root(model, context)
            .or_else(|| sibling_anchor(model, context))
            .map(|root| (root, None)),
    }
}

/// The sibling root and the commands after its `cd`, when the `cd` is
/// followed by `&&` or `;`, every later separator is `&&`, and the verified
/// target is a repository root outside the session's own workspace.
fn sibling_list(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> Option<(PathBuf, CanonicalCommandV1)> {
    let target = super::super::segment_proof::verified_cwd_list_context(model, context, true)?;
    let workspace = std::fs::canonicalize(context.cwd?).ok()?;
    let target = PathBuf::from(target);
    // The sink joins only an `&&` list after a sibling root; a pipe would
    // leave the `cd` to run under the session workspace's profile.
    if target.starts_with(&workspace)
        || model
            .segments
            .iter()
            .any(|segment| segment.pipeline_index != 0)
        || super::super::contained_wrapper::sibling_project_root(&target, context.home_dir?)
            .as_deref()
            != Some(target.as_path())
    {
        return None;
    }
    let mut rest = model.clone();
    rest.segments.remove(0);
    Some((target, rest))
}

/// The repository root for `cd <absolute dir in a sibling repository> &&
/// <one command>`, optionally ending in `2>&1` and `| tail -N`: a directory
/// below the root, such as a worktree package, or the root itself with an
/// output filter. The sink peels the same shape and, holding a workspace
/// receipt, runs the text as issued from that root, so the `cd` stays below
/// the workspace the sandbox confines. Every path the command names that
/// exists must resolve into the root or, for a linked worktree, its main
/// checkout: the trees the sandbox can read. A `node_modules` link into
/// another directory keeps its review instead of failing in the sandbox.
/// `cd <dir> 2>/dev/null; <one command>` runs the command from the root when
/// the `cd` fails, so its paths must be readable from there too.
fn sibling_cd_root(model: &CanonicalCommandV1, context: PathContext<'_>) -> Option<PathBuf> {
    let [spelled] = model.segments.first()?.arguments.as_slice() else {
        return None;
    };
    if !Path::new(spelled).is_absolute() {
        return None;
    }
    let sequenced =
        super::super::segment_proof::verified_cwd_compound_context(model, context).is_none();
    let target = super::super::segment_proof::verified_cwd_list_context(model, context, true)?;
    let target = PathBuf::from(target);
    let workspace = std::fs::canonicalize(context.cwd?).ok()?;
    if target.starts_with(&workspace) {
        return None;
    }
    let root = super::super::contained_wrapper::sibling_project_root(&target, context.home_dir?)?;
    let core = if sequenced {
        sequenced_core(model)?
    } else {
        super::super::contained_wrapper::contained_core(model, context)?
    };
    let trees = readable_trees(&root);
    core.segments
        .iter()
        .all(|segment| {
            names_readable(segment, &target, &trees)
                && (!sequenced || names_readable(segment, &root, &trees))
        })
        .then_some(root)
}

/// The one plain command after `cd <dir>;`, with no other list, pipe or
/// redirect.
fn sequenced_core(model: &CanonicalCommandV1) -> Option<CanonicalCommandV1> {
    let [cd, core] = model.segments.as_slice() else {
        return None;
    };
    let rest: String = model.normalized_text.chars().skip(cd.span.end).collect();
    if model.confidence != "exact"
        || core.pipeline_index != 0
        || core.executable.as_deref() == Some("cd")
        || rest.matches(';').count() != 1
        || rest.contains(['<', '>', '|', '&'])
    {
        return None;
    }
    let mut peeled = model.clone();
    peeled.segments = vec![core.clone()];
    Some(peeled)
}

/// The repository root for one plain command whose first absolute word
/// names an existing path in a sibling repository: a script (`python3
/// <root>/scripts/report.py`), a module (`python3 -m py_compile <path>`) or an
/// installed tool (`bun <root>/node_modules/vite/bin/vite.js build`). The sink
/// runs the text as issued from that root (`anchored_sibling_root`), as for
/// `cd <root> && …`, under the same root rules: a directory with no
/// repository, such as a private temporary or plain home directory, has
/// none. A relative word that names a path from the session directory would
/// name another one there, so that command keeps its review. The session's
/// own repository is no sibling: a root that holds it, or a path inside it,
/// keeps the review, as in `anchored_sibling_root`. Below a temporary
/// directory, where any session can `git init`, the root must be a linked
/// worktree of a checkout in home or outside the temporary directories.
fn sibling_anchor(model: &CanonicalCommandV1, context: PathContext<'_>) -> Option<PathBuf> {
    let [segment] = model.segments.as_slice() else {
        return None;
    };
    let executable = segment.executable.as_deref()?;
    if model.confidence != "exact"
        || !model.wrapper_chain.is_empty()
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || segment.pipeline_index != 0
        || executable == "cd"
        || model
            .normalized_text
            .contains(['<', '>', '|', '&', ';', '$', '`'])
    {
        return None;
    }
    let (cwd, home) = (std::fs::canonicalize(context.cwd?).ok()?, context.home_dir?);
    let workspace = super::super::contained_wrapper::sibling_project_root(&cwd, home)
        .unwrap_or_else(|| cwd.clone());
    let words = || std::iter::once(executable).chain(segment.arguments.iter().map(String::as_str));
    let anchor = std::fs::canonicalize(executed_path(executable, &segment.arguments)?).ok()?;
    let root = super::super::contained_wrapper::sibling_project_root(&anchor, home)?;
    if anchor.starts_with(&workspace)
        || root.starts_with(&workspace)
        || workspace.starts_with(&root)
        || !temporary_anchor_trusted(&root, home)
        || words().any(|word| {
            let value = word_path(word);
            !value.is_empty()
                && !Path::new(value).is_absolute()
                && std::fs::symlink_metadata(cwd.join(value)).is_ok()
        })
    {
        return None;
    }
    names_readable(segment, &root, &readable_trees(&root)).then_some(root)
}

/// The absolute path a command runs from a sibling: the executable itself
/// (`<root>/node_modules/.bin/vite build`), the script an interpreter is given
/// first (`bun <root>/scripts/x.ts`), or the file `python3 -m py_compile`
/// checks. A path that is only an operand (`rm`, `jq`, `rg`, `cat <root>/f`)
/// runs nothing from the sibling, so it keeps its own proof or review.
fn executed_path<'a>(executable: &'a str, arguments: &'a [String]) -> Option<&'a str> {
    let absolute = |word: &&str| Path::new(word).is_absolute();
    if absolute(&executable) {
        return Some(executable);
    }
    let name = super::super::executable_basename(executable);
    let python = name == "python"
        || name.strip_prefix("python3").is_some_and(|minor| {
            minor.is_empty()
                || minor.strip_prefix('.').is_some_and(|minor| {
                    !minor.is_empty() && minor.bytes().all(|b| b.is_ascii_digit())
                })
        });
    match arguments {
        [module, compiler, path, ..]
            if python
                && module == "-m"
                && matches!(compiler.as_str(), "py_compile" | "compileall") =>
        {
            Some(path.as_str()).filter(absolute)
        }
        [script, ..] if python || SCRIPT_RUNNERS.contains(&name) => {
            Some(script.as_str()).filter(absolute)
        }
        _ => None,
    }
}

/// Interpreters whose first operand is the script they run.
const SCRIPT_RUNNERS: &[&str] = &[
    "node", "bun", "deno", "tsx", "ts-node", "ruby", "perl", "sh", "bash",
];

/// Whether `root` lies in home or outside the shared temporary directories
/// (`/tmp`, `/var/folders`, `$TMPDIR`), or is a linked worktree whose shared
/// `.git` does.
fn temporary_anchor_trusted(root: &Path, home: &str) -> bool {
    let home = std::fs::canonicalize(home).ok();
    let mut temporary: Vec<PathBuf> = ["/tmp", "/private/tmp", "/var/folders"]
        .into_iter()
        .map(PathBuf::from)
        .chain(std::env::var_os("TMPDIR").map(PathBuf::from))
        .filter(|path| path.is_absolute())
        .collect();
    temporary.extend(
        temporary
            .iter()
            .filter_map(|path| std::fs::canonicalize(path).ok())
            .collect::<Vec<_>>(),
    );
    let trusted = |path: &Path| {
        home.as_ref().is_some_and(|home| path.starts_with(home))
            || !temporary.iter().any(|base| path.starts_with(base))
    };
    trusted(root)
        || super::super::worktree_writes::linked_worktree_dirs(root)
            .is_some_and(|(common, _)| trusted(&common))
}

/// The trees the sandbox rooted at `root` can read: the root and, for a
/// linked worktree, its main checkout.
fn readable_trees(root: &Path) -> Vec<PathBuf> {
    let mut trees = vec![root.to_path_buf()];
    if let Some(checkout) = super::super::worktree_writes::linked_worktree_common_dir(root)
        .and_then(|common| common.parent().map(Path::to_path_buf))
    {
        trees.push(checkout);
    }
    trees
}

/// The path a word names: the value of a `--option=value` word, else the word.
fn word_path(word: &str) -> &str {
    match word.split_once('=') {
        Some((option, value)) if option.starts_with('-') => value,
        _ => word,
    }
}

/// Whether every word of `segment` that names an existing path from
/// `directory` resolves below one of `trees`.
fn names_readable(segment: &CommandSegmentV1, directory: &Path, trees: &[PathBuf]) -> bool {
    segment
        .executable
        .iter()
        .chain(&segment.arguments)
        .all(|word| {
            let value = word_path(word);
            let path = directory.join(value);
            value.is_empty()
                || std::fs::symlink_metadata(&path).is_err()
                || std::fs::canonicalize(&path)
                    .is_ok_and(|resolved| trees.iter().any(|tree| resolved.starts_with(tree)))
        })
}
