//! `rg -g '!NAME'` exclusions, and the review reason that suggests one.
//!
//! An `rg` search of a sibling repository is held when a sensitive file, such
//! as a test TLS key, sits below the folder it names. The reason used to say
//! only that the command "could not be confirmed read-only", and agents could
//! not tell which file held it or how to leave it out. `grep -r` already names
//! the file and accepts `--exclude-dir`; this does the same for `rg`.
//!
//! An override glob outranks every ignore file, so `rg` neither enters a
//! directory nor reads a file whose name a `!NAME` glob matches. Only plain
//! names count, and only while every glob of the command is one: a later
//! inclusion glob can re-include what an earlier exclusion left out.
use super::{rg, sibling, ReadContext};

/// Exclusions a suggestion may add before it gives up.
const MAX_SUGGESTED: usize = 3;

/// The names `globs` leave out, when every glob is `!NAME` with a plain
/// `NAME`. Empty when any glob is something else.
pub(super) fn excluded_names(globs: &[&str]) -> Vec<String> {
    let names: Option<Vec<String>> = globs
        .iter()
        .map(|glob| {
            glob.strip_prefix('!')
                .filter(|name| plain_name(name))
                .map(str::to_owned)
        })
        .collect();
    names.unwrap_or_default()
}

/// A name of letters, digits, `_`, `-` and `.` that matches only itself.
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// A review reason for a command that is one `rg` plus filters of its output,
/// held because a sensitive entry sits below a sibling-repository folder it
/// searches. The reason names that entry and the `-g '!NAME'` exclusions with
/// which the same command is proven. `None` for every other command, and when
/// no such exclusion would release it.
pub(in crate::pretool) fn rg_sensitive_reach_reason(
    model: &crate::CanonicalCommandV1,
    context: ReadContext<'_>,
) -> Option<String> {
    if model.confidence != "exact" || model.path_overridden || !model.wrapper_chain.is_empty() {
        return None;
    }
    let mut found = None;
    for segment in &model.segments {
        let is_rg = segment
            .executable
            .as_deref()
            .is_some_and(|name| crate::pretool::executable_basename(name) == "rg");
        if is_rg && found.is_none() {
            found = Some(segment);
        } else if !crate::pretool::segment_proof::stdin_filter_segment(segment) {
            return None;
        }
    }
    let segment = found.filter(|segment| segment.environment_names.is_empty())?;
    let roots = operands(&segment.arguments);
    let mut trial = segment.clone();
    let mut first: Option<String> = None;
    let mut suggested: Vec<String> = Vec::new();
    for _ in 0..=MAX_SUGGESTED {
        if rg::safe_rg_segment(model, &trial, context) {
            let shown = first?;
            let globs = suggested
                .iter()
                .map(|name| format!("-g '!{name}'"))
                .collect::<Vec<_>>()
                .join(" ");
            return Some(format!(
                "HOL Guard requires review because the search would reach `{shown}`, which Guard treats as sensitive. Leave out the folder that holds it, for example by naming the folders you need instead of the whole tree, or skip it with `{globs}`."
            ));
        }
        if suggested.len() == MAX_SUGGESTED {
            return None;
        }
        let excluded = excluded_names(&written_globs(&trial.arguments)?);
        let (root, entry) = roots.iter().find_map(|root| {
            sibling::rg_sibling_sensitive_entry(root, context, &excluded)
                .map(|entry| (root.as_str(), entry))
        })?;
        let name = suggested_name(root, &entry, context)?;
        if excluded.contains(&name) {
            return None;
        }
        if first.is_none() {
            let folder = root.trim_end_matches('/');
            let shown = format!("{folder}/{entry}");
            let printable = shown.len() <= 512
                && !shown.contains(['`', '\''])
                && !shown.chars().any(char::is_control);
            first = Some(printable.then_some(shown)?);
        }
        (trial.arguments).splice(0..0, ["-g".to_owned(), format!("!{name}")]);
        suggested.push(name);
    }
    None
}

/// The name to leave out for `entry` below `root`: the entry itself when it is
/// a directory, otherwise the folder that holds it, or the file when it sits
/// directly in the root. A folder of test keys usually holds the matching
/// certificates too.
fn suggested_name(root: &str, entry: &str, context: ReadContext<'_>) -> Option<String> {
    let parts: Vec<&str> = entry.split('/').collect();
    let path = super::tree::expanded_operand(root, context)?.join(entry);
    let is_dir = std::fs::symlink_metadata(path).ok()?.is_dir();
    let name = match parts.as_slice() {
        [.., last] if is_dir => last,
        [.., parent, _] => parent,
        [only] => only,
        [] => return None,
    };
    plain_name(name).then(|| (*name).to_owned())
}

/// The `-g`/`--glob` values as written. `None` when a glob is spelled in a
/// form this does not read (`--iglob`, a short cluster): no suggestion then.
fn written_globs(arguments: &[String]) -> Option<Vec<&str>> {
    let mut globs = Vec::new();
    let mut pending = false;
    for argument in arguments {
        if std::mem::take(&mut pending) {
            globs.push(argument.as_str());
            continue;
        }
        if argument == "--" {
            break;
        }
        if argument == "-g" || argument == "--glob" {
            pending = true;
        } else if let Some(glob) = (argument.strip_prefix("--glob="))
            .or_else(|| argument.strip_prefix("-g").filter(|glob| !glob.is_empty()))
        {
            globs.push(glob);
        } else if argument.starts_with("--iglob")
            || (argument.starts_with('-') && !argument.starts_with("--") && argument.contains('g'))
        {
            return None;
        }
    }
    Some(globs)
}

/// The path operands of an `rg` call, read as advice: the first positional is
/// the pattern unless an option supplies one.
fn operands(arguments: &[String]) -> Vec<String> {
    let mut positionals = Vec::new();
    let mut pattern_from_option = false;
    let mut skip = false;
    let mut options = true;
    for argument in arguments {
        if std::mem::take(&mut skip) {
            continue;
        }
        if options && argument == "--" {
            options = false;
        } else if options && argument.starts_with("--") {
            let name = argument
                .split_once('=')
                .map_or(argument.as_str(), |pair| pair.0);
            pattern_from_option |= matches!(name, "--regexp" | "--file" | "--files");
            skip = !argument.contains('=') && super::options::rg_value_role(name).is_some();
        } else if options && argument.starts_with('-') && argument.len() > 1 {
            let short = &argument[1..];
            let at = short.find(|option| "efgABCEjmMrtT".contains(option));
            pattern_from_option |= at.is_some_and(|at| matches!(&short[at..=at], "e" | "f"));
            skip = at.is_some_and(|at| at + 1 == short.len());
        } else {
            positionals.push(argument.clone());
        }
    }
    if !pattern_from_option && !positionals.is_empty() {
        positionals.remove(0);
    }
    positionals
}

#[cfg(all(test, unix))]
#[path = "rg_exclusions_tests.rs"]
mod tests;
