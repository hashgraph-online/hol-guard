//! Oh My Pi's `ls`, `glob` and `find` list names, and `grep` walks a search
//! scope. Both proofs answer the same question: does every path the selector
//! can reach stay inside the session, under a folder the user already works
//! in? The helpers here bound brace expansions and `;`-separated path lists
//! before the walk is judged.

use super::grep_glob::glob_directory;
use super::{
    contained_selector, directory_allow, generic_action, generic_result, input_path, scalar_keys,
    strict_tool_input, GenericSignals, OmpContext,
};
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1};
use serde_json::Value;

pub(super) fn listing(
    payload: &Value,
    signals: &GenericSignals,
    context: &OmpContext<'_>,
) -> Option<PreToolResultV1> {
    let input = strict_tool_input(payload)?;
    if !scalar_keys("glob", input, &["path", "pattern"]) {
        return None;
    }
    if let Some(pattern) = input.get("pattern") {
        if !contained_selector(pattern.as_str()?) {
            return None;
        }
    }
    let recursive = signals.tool_name.as_deref() == Some("find") || input.contains_key("pattern");
    let gitignore = input.get("gitignore").and_then(Value::as_bool) != Some(false);
    let targets = search_targets(input_path(input, signals)?.unwrap_or("."), context)?;
    let proven =
        |target: &str| listing_target_proven(target, signals, (recursive, gitignore), context);
    if targets.iter().all(|target| proven(target)) {
        return Some(directory_allow(
            context,
            "native_omp_directory_listing",
            "The Rust authority proved this names-only listing targets a verified ordinary directory.",
        ));
    }
    // A literal path that names nothing lists nothing, so stopping the call
    // costs nothing. A read of the same path gets the same answer, so saying
    // why reveals no more and lets the agent fix the path instead of waiting
    // on an approval. Sensitive names keep their review.
    let (home, cwd) = (context.path.home_dir, context.path.cwd);
    let missing = |target: &str| {
        !signals.sensitive_target
            && super::super::read_paths::missing_read_target(target, home, cwd, false)
            && !super::super::sensitive_command(target)
            && !super::super::sensitive_read_path_argument(target)
    };
    // A name inside a linked worktree this repository registers lists nothing
    // when nothing is there, and every existing file in that worktree is
    // already routed, so saying nothing is there reveals no more than a
    // listing the agent may already run.
    let registered = |target: &str| {
        missing(target)
            && super::super::git_routes::missing_path_in_registered_worktree(target, home, cwd)
    };
    if targets
        .iter()
        .all(|target| proven(target) || registered(target))
    {
        return Some(directory_allow(
            context,
            "native_missing_worktree_listing",
            "The Rust authority proved this listing names a path with nothing behind it inside a linked worktree this repository registers, so it lists nothing and the tool reports the missing path itself.",
        ));
    }
    targets
        .iter()
        .all(|target| proven(target) || missing(target))
        .then(|| {
            let mut result = generic_result(
                generic_action(
                    context.harness,
                    context.event,
                    PreToolActionTypeV1::FileRead,
                    PreToolOperationV1::Read,
                    true,
                    false,
                ),
                "block",
                super::read_decisions::MISSING_PATH,
                "",
            );
            result.reason = super::read_decisions::missing_path_reason(
                "HOL Guard did not run this listing because its path does not exist. Check the path, for example by listing its parent directory, and try again with the correct one.",
                "listing",
                targets.iter().find(|target| !proven(target)).copied(),
            );
            result
        })
}

fn listing_target_proven(
    target: &str,
    signals: &GenericSignals,
    (recursive, gitignore): (bool, bool),
    context: &OmpContext<'_>,
) -> bool {
    if signals.tool_name.as_deref() == Some("glob") && target.contains(['{', '}']) {
        // Below a literal directory the host matches the alternatives
        // relative to it. Without that prefix it searches `**/<pattern>` from
        // the cwd (`parseFindPattern`), so each expansion is proven that way:
        // the same proof as an unbraced `**/*.sh`, never wider.
        let anchored = target
            .find(['*', '?', '[', '{'])
            .is_some_and(|index| target[..index].contains('/'));
        let (options, walk) = ((recursive, gitignore), (true, gitignore));
        return brace_expansions(target).is_some_and(|expansions| {
            expansions.iter().all(|expansion| {
                if anchored || expansion.starts_with("**/") {
                    return listing_target_proven(expansion, signals, options, context);
                }
                contained_selector(expansion)
                    && listing_target_proven(&format!("**/{expansion}"), signals, walk, context)
            })
        });
    }
    let has_glob_selector =
        signals.tool_name.as_deref() == Some("glob") && target.contains(['*', '?', '[', '{']);
    let selector = target;
    // OMP glob uses `path` for the complete selector, not just a directory.
    // Prove its fixed directory prefix; the tool returns names, not contents.
    let target = if signals.tool_name.as_deref() == Some("glob") {
        match glob_directory(target) {
            Some(directory) => directory,
            None => return false,
        }
    } else {
        target
    };
    // A wildcard walks below its literal prefix and, like `find`, returns
    // names only, so the walk from that prefix is held to the same rules.
    // Outside the workspace no sensitive name may be reachable below it.
    // The proof is skipped when the walk starts inside the session folder and
    // the last component is a literal ordinary name: then every name the host
    // returns ends in that name.
    // Below a literal directory the host runs the selector with recursion
    // off, so a one-segment selector such as `dir/*lock*` returns only that
    // directory's own entries: the names a listing of it returns. Outside the
    // session folder the stricter walk below still applies.
    let single_level = has_glob_selector
        && !recursive
        && single_level_selector(selector)
        && walk_inside_session(target, context);
    let recursive = (recursive || has_glob_selector) && !single_level;
    let literal_name = has_glob_selector
        && literal_name_selector(selector)
        && walk_inside_session(target, context);
    if has_glob_selector
        && !literal_name
        && !single_level
        && !super::super::search_scope::omp_glob_scope_proven(
            target,
            context.path.home_dir,
            context.path.cwd,
            gitignore,
        )
    {
        return false;
    }
    // `find` and a `pattern` walk the tree below the root and return names
    // only, so an ordinary project root is fine even with a `.env` inside;
    // reading that file stays gated. A walk from the home directory or above
    // it reaches credential stores and agent state, so it stays on review,
    // and so does a literal-name glob that skipped the tree proof.
    if (recursive || literal_name) && walk_covers_home(target, context) {
        return false;
    }
    // A glob entry without wildcards matches only itself, so the host returns
    // that one name. A file there carries the bounded file-read proof.
    let literal_glob_file = signals.tool_name.as_deref() == Some("glob")
        && !has_glob_selector
        && super::super::read_paths::existing_regular_read_target(
            target,
            context.path.home_dir,
            context.path.cwd,
        );
    let missing_glob_entry = signals.tool_name.as_deref() == Some("glob")
        && !has_glob_selector
        && missing_listing_entry(target, context);
    literal_glob_file
        || missing_glob_entry
        || super::super::safe_reads::bounded_omp_directory_read_target(
            target,
            context.path.home_dir,
            context.path.cwd,
        )
        || home_dot_directory_listing(target, has_glob_selector, recursive, context)
        || (!has_glob_selector && project_skill_listing(target, context))
}

/// A names-only listing of a dot-directory in the home directory, the same
/// one `ls ~/.nvm` already gets.
///
/// The shared screen is bounded to the directory's own entries, because a
/// walk below `~/.config` prints the names inside `~/.config/gh`. The host
/// recurses only for `find` or a `pattern`, and a selector walks below its
/// prefix, so both are left out and the entry names of one directory are
/// what remains.
fn home_dot_directory_listing(
    target: &str,
    has_glob_selector: bool,
    recursive: bool,
    context: &OmpContext<'_>,
) -> bool {
    !has_glob_selector
        && !recursive
        && super::super::read_paths::home_hidden_directory(
            target,
            context.path.home_dir,
            context.path.cwd,
        )
}

/// A names-only listing of the session's own project skill folders. Only a
/// literal path with no link component is resolved; the screens are in
/// `project_skill_listing_directory`.
fn project_skill_listing(target: &str, context: &OmpContext<'_>) -> bool {
    let (Some(home), Some(cwd)) = (context.path.home_dir, context.path.cwd) else {
        return false;
    };
    if target.is_empty()
        || target.trim() != target
        || target.len() > 4096
        || target.contains(['\\', '$', '`', '\0', '\n', '\r'])
        || target.split('/').any(|part| part == "..")
    {
        return false;
    }
    let candidate = match target.strip_prefix("~/") {
        Some(rest) => std::path::Path::new(home).join(rest),
        None if target.starts_with('~') => return false,
        None => std::path::Path::new(cwd).join(target),
    };
    if guard_secure_fs::contains_symlink_component(&candidate) {
        return false;
    }
    let (Ok(canonical), Ok(session)) = (
        std::fs::canonicalize(&candidate),
        std::fs::canonicalize(cwd),
    ) else {
        return false;
    };
    super::super::read_paths::project_skill_listing_directory(&canonical, &session)
        && super::super::read_paths::resolved_location_allowed(
            &canonical,
            context.path.home_dir,
            context.path.cwd,
            false,
        )
}

/// Whether a glob selector is a literal directory followed by one wildcard
/// segment, such as `src/*.ts`. Oh My Pi matches that segment against the
/// directory's own entries only: its glob tool passes `recursive: false` and
/// its input schema has no field that turns recursion on (checked in Oh My Pi
/// 18.4.12, 18.8.3 and 18.11.3). `listing` rejects any key outside that schema, and a
/// `pattern` key keeps the walk. A selector with no literal directory gains
/// a `**/` prefix there, and `**` crosses directories, so neither is
/// single-level.
fn single_level_selector(selector: &str) -> bool {
    let Some(index) = selector.find(['*', '?', '[', '{']) else {
        return false;
    };
    let Some(slash) = selector[..index].rfind('/') else {
        return false;
    };
    let segment = &selector[slash + 1..];
    !segment.is_empty() && !segment.contains('/') && !segment.contains("**")
}

/// Whether a glob selector ends in a literal file name, such as
/// `docs/**/AGENTS.md`, that names no credential or sensitive location.
fn literal_name_selector(selector: &str) -> bool {
    let Some((_, name)) = selector.rsplit_once('/') else {
        return false;
    };
    // The host may match case-insensitively, so judge the lowered name too.
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['*', '?', '[', ']', '{', '}', '\\'])
        && !name.chars().any(char::is_control)
        && [name.to_owned(), name.to_ascii_lowercase()]
            .iter()
            .all(|name| {
                !super::super::sensitive_read_path_argument(name)
                    && !super::super::sensitive_command(name)
            })
}

/// A glob entry that names nothing returns no names: the host skips it in a
/// list and reports it missing, or fails a single path with "not found". It
/// reveals no more than a listing of its nearest existing folder, so it
/// carries that folder's listing proof when it sits in the session folder.
/// Sensitive and hidden names keep their review.
fn missing_listing_entry(target: &str, context: &OmpContext<'_>) -> bool {
    let (home, cwd) = (context.path.home_dir, context.path.cwd);
    if !super::super::read_paths::missing_read_target(target, home, cwd, false)
        || super::super::sensitive_command(target)
        || super::super::sensitive_read_path_argument(target)
        || target.split(['/', '\\']).any(|part| part == "..")
    {
        return false;
    }
    let expand = |path: &str| {
        super::super::read_paths::expand_home_read_path(path, home)
            .unwrap_or_else(|| path.to_owned())
    };
    let Some(session) = cwd.and_then(|root| std::fs::canonicalize(expand(root)).ok()) else {
        return false;
    };
    let path = session.join(expand(target));
    let Some(folder) = path
        .ancestors()
        .skip(1)
        .find(|folder| std::fs::symlink_metadata(folder).is_ok())
    else {
        return false;
    };
    let (Ok(canonical), Ok(missing)) = (std::fs::canonicalize(folder), path.strip_prefix(folder))
    else {
        return false;
    };
    // Only an ordinary folder inside the session qualifies, and no name on
    // the way down from the session may be hidden.
    let visible = |path: &std::path::Path| {
        path.components().all(|part| {
            matches!(part, std::path::Component::Normal(name)
                if name.to_str().is_some_and(|name| !name.starts_with('.')))
        })
    };
    canonical.is_dir()
        && canonical.strip_prefix(&session).is_ok_and(visible)
        && visible(missing)
        && folder.to_str().is_some_and(|folder| {
            super::super::safe_reads::bounded_omp_directory_read_target(folder, home, cwd)
        })
}

/// Maximum patterns proven from one glob's `{a,b}` alternatives.
const MAX_BRACE_EXPANSIONS: usize = 32;

/// Every pattern a glob's `{a,b}` groups expand to. Nested, unmatched or
/// escaped groups, and expansions past the bound, return `None`.
fn brace_expansions(target: &str) -> Option<Vec<String>> {
    if target.contains('\\') {
        return None;
    }
    let mut expansions = vec![String::new()];
    let mut rest = target;
    while let Some(open) = rest.find(['{', '}']) {
        if rest.as_bytes()[open] == b'}' {
            return None;
        }
        let close = open + 1 + rest[open + 1..].find(['{', '}'])?;
        if rest.as_bytes()[close] == b'{' {
            return None;
        }
        let alternatives: Vec<&str> = rest[open + 1..close].split(',').collect();
        if expansions.len() * alternatives.len() > MAX_BRACE_EXPANSIONS {
            return None;
        }
        let literal = &rest[..open];
        expansions = expansions
            .iter()
            .flat_map(|prefix| {
                alternatives
                    .iter()
                    .map(move |alternative| format!("{prefix}{literal}{alternative}"))
            })
            .collect();
        rest = &rest[close + 1..];
    }
    for expansion in &mut expansions {
        expansion.push_str(rest);
    }
    Some(expansions)
}

/// Maximum entries proven from one semicolon-delimited `path`.
const MAX_SEARCH_TARGETS: usize = 32;

/// The entries an OMP search tool walks for one `path` string. When the whole
/// string is not an existing path, the host splits it on every top-level `;`
/// before trying any other delimiter (`splitDelimitedPathEntry`), so
/// `src; ../notes` searches both entries. Each returned entry still needs its
/// own proof. `None` keeps review when the host's split could differ from this
/// one: braces and escapes change what counts as top level, quotes are peeled
/// per entry, and an existing literal or selector base is kept whole.
pub(super) fn search_targets<'a>(
    target: &'a str,
    context: &OmpContext<'_>,
) -> Option<Vec<&'a str>> {
    if !target.contains(';') {
        return Some(vec![target]);
    }
    if target.trim() != target
        || target.starts_with('[')
        || target.contains(['{', '}', '\\', '"', '\0', '\n', '\r'])
    {
        return None;
    }
    let literal_absent = |candidate: &str| {
        let path = match candidate.strip_prefix("~/") {
            Some(rest) => std::path::Path::new(context.path.home_dir?).join(rest),
            None => std::path::Path::new(context.path.cwd?).join(candidate),
        };
        match std::fs::symlink_metadata(path) {
            Err(error) => Some(error.kind() == std::io::ErrorKind::NotFound),
            Ok(_) => Some(false),
        }
    };
    if literal_absent(target) != Some(true) {
        return None;
    }
    if let Some((base, _)) = target.rsplit_once(':') {
        if literal_absent(base) != Some(true) {
            return None;
        }
    }
    let targets: Vec<&str> = target
        .split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    (!targets.is_empty() && targets.len() <= MAX_SEARCH_TARGETS).then_some(targets)
}

/// True when the walk root is the home directory or one of its ancestors,
/// or when either cannot be resolved.
fn walk_covers_home(target: &str, context: &OmpContext<'_>) -> bool {
    let (Some(home), Some(cwd)) = (context.path.home_dir, context.path.cwd) else {
        return true;
    };
    let root = if target == "~" {
        std::path::PathBuf::from(home)
    } else if let Some(rest) = target.strip_prefix("~/") {
        std::path::Path::new(home).join(rest)
    } else {
        std::path::Path::new(cwd).join(target)
    };
    match (std::fs::canonicalize(root), std::fs::canonicalize(home)) {
        (Ok(root), Ok(home)) => home.starts_with(root),
        _ => true,
    }
}

pub(super) fn walk_inside_session(target: &str, context: &OmpContext<'_>) -> bool {
    let Some(cwd) = context.path.cwd else {
        return false;
    };
    if target.starts_with('~') {
        return false;
    }
    match (
        std::fs::canonicalize(std::path::Path::new(cwd).join(target)),
        std::fs::canonicalize(cwd),
    ) {
        (Ok(root), Ok(cwd)) => root.starts_with(cwd),
        _ => false,
    }
}
