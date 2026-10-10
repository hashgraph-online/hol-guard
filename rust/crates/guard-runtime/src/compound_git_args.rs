//! Hand-written argument-shape validators for bounded Git inspection. Every
//! pattern is matched byte-for-byte (no regular-expression engine), so there is
//! no engine error path to fail open on; unmatched input is a refusal.

const MAX_REF_TAIL: usize = 255;
const MAX_COMPONENT_TAIL: usize = 127;
const STATUS_WORDS: [&str; 4] = ["--short", "--branch", "--porcelain", "--porcelain=v1"];
const FETCH_FLAGS: [&str; 3] = ["-q", "--quiet", "--no-tags"];
const DIFF_WORDS: [&str; 6] = [
    "--check",
    "--stat",
    "--name-only",
    "--name-status",
    "--cached",
    "HEAD",
];
const SHOW_OPTIONS: [&str; 4] = ["--stat", "--oneline", "--name-only", "--name-status"];
const OBJECT_TYPES: [&str; 5] = ["blob", "commit", "object", "tag", "tree"];

fn is_alnum(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

/// `[A-Za-z0-9][A-Za-z0-9._/-]{0,tail}` over the whole string.
fn matches_ref_class(value: &str, tail: usize) -> bool {
    let bytes = value.as_bytes();
    bytes.first().is_some_and(|first| is_alnum(*first))
        && bytes.len() <= tail + 1
        && bytes[1..]
            .iter()
            .all(|byte| is_alnum(*byte) || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

/// `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}` over the whole string.
pub(crate) fn is_path_component(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes
        .first()
        .is_some_and(|first| is_alnum(*first) || *first == b'_')
        && bytes.len() <= MAX_COMPONENT_TAIL + 1
        && bytes[1..]
            .iter()
            .all(|byte| is_alnum(*byte) || matches!(byte, b'_' | b'.' | b'-'))
}

/// Only ASCII digits count. Python's `str.isdigit` also accepts non-ASCII
/// digit characters; refusing them is the stricter direction.
pub(crate) fn all_ascii_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// A decimal value, saturating on overflow so oversized counts stay out of range.
pub(crate) fn saturating_number(digits: &str) -> u64 {
    digits.parse::<u64>().unwrap_or(u64::MAX)
}

pub(crate) fn is_dynamic(value: &str) -> bool {
    value
        .chars()
        .any(|ch| matches!(ch, '$' | '`' | '<' | '>' | '|' | ';' | '&' | '\0'))
}

pub(crate) fn safe_ref(value: &str) -> bool {
    if let Some(count) = value.strip_prefix("HEAD~") {
        let bytes = count.as_bytes();
        if (1..=4).contains(&bytes.len())
            && matches!(bytes[0], b'1'..=b'9')
            && bytes.iter().all(u8::is_ascii_digit)
        {
            return true;
        }
    }
    matches_ref_class(value, MAX_REF_TAIL)
        && !value.contains("..")
        && !value.ends_with('.')
        && !value.ends_with('/')
}

/// Exact object-existence operand: a ref-class name with an optional `^` or
/// `^{blob|commit|object|tag|tree}` suffix.
pub(crate) fn safe_object_existence_operand(value: &str) -> bool {
    let (base, suffix) = match value.find('^') {
        Some(index) => value.split_at(index),
        None => (value, ""),
    };
    let suffix_ok = suffix.is_empty()
        || suffix == "^"
        || suffix
            .strip_prefix("^{")
            .and_then(|rest| rest.strip_suffix('}'))
            .is_some_and(|kind| OBJECT_TYPES.contains(&kind));
    suffix_ok && matches_ref_class(base, MAX_REF_TAIL)
}

fn components_are_safe<'a>(components: impl IntoIterator<Item = &'a str>) -> bool {
    components
        .into_iter()
        .all(|component| !matches!(component, "" | "." | "..") && is_path_component(component))
}

pub(crate) fn safe_repository_path(value: &str) -> bool {
    if value == "." {
        return true;
    }
    if value.is_empty()
        || value.chars().count() > 512
        || value.starts_with('/')
        || value.starts_with('~')
        || is_dynamic(value)
    {
        return false;
    }
    let normalized = value.strip_suffix('/').unwrap_or(value);
    let mut components: Vec<&str> = normalized.split('/').collect();
    if components.first() == Some(&".") {
        components.remove(0);
    }
    !components.is_empty() && components_are_safe(components)
}

/// `:!<path>` / `:^<path>` exclusion pathspec with a safe repository path.
fn safe_exclude_pathspec(value: &str) -> bool {
    let Some(remainder) = value
        .strip_prefix(":!")
        .or_else(|| value.strip_prefix(":^"))
    else {
        return false;
    };
    !remainder.is_empty()
        && !remainder.starts_with([':', '/', '~'])
        && safe_repository_path(remainder)
}

/// Pathspecs after `--` in a staged diff: every one must be a safe repository
/// path or a safe exclusion. An empty list is not a path scope.
pub(crate) fn safe_cached_diff_pathspecs(values: &[String]) -> bool {
    !values.is_empty()
        && values
            .iter()
            .all(|value| safe_repository_path(value) || safe_exclude_pathspec(value))
}

/// Components of a `~/` tail after the prefix.
pub(crate) fn safe_home_tail(tail: &str) -> bool {
    !tail.is_empty()
        && !tail.starts_with('/')
        && !tail.starts_with('\\')
        && components_are_safe(tail.split('/'))
}

pub(crate) fn safe_git_c_repository_path(value: &str, home_dir_present: bool) -> bool {
    if safe_repository_path(value) {
        return true;
    }
    if let Some(tail) = value.strip_prefix("~/") {
        return home_dir_present && safe_home_tail(tail);
    }
    if value.is_empty()
        || value.chars().count() > 512
        || !value.starts_with('/')
        || is_dynamic(value)
    {
        return false;
    }
    // Path.parts drops empty and "." components; ".." stays and is refused.
    components_are_safe(
        value
            .split('/')
            .filter(|component| !component.is_empty() && *component != "."),
    )
}

/// `git[ \t]+-C[ \t]+(~/[A-Za-z0-9_.\-/]+)` followed by a space or tab.
pub(crate) fn canonical_home_git_c_path(command_text: &str) -> Option<String> {
    let blank = |byte: &u8| matches!(byte, b' ' | b'\t');
    let rest = command_text.strip_prefix("git")?;
    let rest = skip_blanks(rest, blank)?;
    let rest = rest.strip_prefix("-C")?;
    let rest = skip_blanks(rest, blank)?;
    let after_tilde = rest.strip_prefix("~/")?;
    let run = after_tilde
        .bytes()
        .take_while(|byte| is_alnum(*byte) || matches!(byte, b'_' | b'.' | b'-' | b'/'))
        .count();
    if run == 0 || !after_tilde.as_bytes().get(run).is_some_and(blank) {
        return None;
    }
    let tail = &after_tilde[..run];
    components_are_safe(tail.split('/')).then(|| format!("~/{tail}"))
}

fn skip_blanks(text: &str, blank: impl Fn(&u8) -> bool) -> Option<&str> {
    let count = text.bytes().take_while(|byte| blank(byte)).count();
    (count > 0).then(|| &text[count..])
}

pub(crate) fn safe_rev_parse_args(args: &[&str]) -> bool {
    matches!(
        args,
        ["--show-toplevel"] | ["--show-prefix"] | ["--is-inside-work-tree"]
    ) || matches!(args, [single] if safe_ref(single))
}

pub(crate) fn safe_status_arg(value: &str) -> bool {
    if STATUS_WORDS.contains(&value) {
        return true;
    }
    value.starts_with('-')
        && !value.starts_with("--")
        && value.len() > 1
        && value[1..].bytes().all(|byte| matches!(byte, b'b' | b's'))
}

/// `(?:[^%\r\n]|%(?:H|h|cI|s|an|ae))+` over the whole value, at most 160 chars.
fn safe_log_format(value: &str) -> bool {
    if value.is_empty() || value.chars().count() > 160 {
        return false;
    }
    let mut rest = value;
    while let Some(ch) = rest.chars().next() {
        if ch == '\r' || ch == '\n' {
            return false;
        }
        if ch != '%' {
            rest = &rest[ch.len_utf8()..];
            continue;
        }
        let tail = &rest[1..];
        let consumed = ["H", "h", "cI", "s", "an", "ae"]
            .iter()
            .find(|placeholder| tail.starts_with(**placeholder))
            .map(|placeholder| placeholder.len());
        let Some(consumed) = consumed else {
            return false;
        };
        rest = &tail[consumed..];
    }
    true
}

pub(crate) fn safe_bounded_log_args(args: &[&str]) -> bool {
    if let [first, format, reference] = args {
        if matches!(*first, "-1" | "-n1") {
            if let Some(format) = format.strip_prefix("--format=") {
                return safe_log_format(format) && safe_ref(reference);
            }
        }
    }
    if args.iter().filter(|arg| **arg == "--oneline").count() != 1 {
        return false;
    }
    let bounds: Vec<&str> = args
        .iter()
        .copied()
        .filter(|arg| arg.strip_prefix('-').is_some_and(all_ascii_digits))
        .collect();
    let [bound] = bounds.as_slice() else {
        return false;
    };
    if !(1..=100).contains(&saturating_number(&bound[1..])) {
        return false;
    }
    let refs: Vec<&str> = args
        .iter()
        .copied()
        .filter(|arg| !matches!(*arg, "--decorate" | "--oneline") && arg != bound)
        .collect();
    refs.len() <= 1 && refs.iter().all(|reference| safe_ref(reference))
}

pub(crate) fn safe_fetch_args(args: &[&str]) -> bool {
    if args.is_empty() || args.len() > 16 {
        return false;
    }
    let mut remote_seen = false;
    let mut refs: Vec<&str> = Vec::new();
    for arg in args {
        if FETCH_FLAGS.contains(arg) {
            continue;
        }
        if arg.starts_with('-') || (!remote_seen && *arg != "origin") {
            return false;
        }
        if !remote_seen {
            remote_seen = true;
            continue;
        }
        refs.push(arg);
    }
    remote_seen && refs.len() <= 12 && refs.iter().all(|reference| safe_ref(reference))
}

pub(crate) fn safe_ls_remote_args(args: &[&str]) -> bool {
    (3..=12).contains(&args.len())
        && args[..2] == ["--heads", "origin"]
        && args[2..].iter().all(|reference| safe_ref(reference))
}

pub(crate) fn safe_branch_args(args: &[&str]) -> bool {
    if matches!(args, ["--show-current"] | ["--list"]) {
        return true;
    }
    (3..=12).contains(&args.len())
        && matches!(args[..2], ["-r", "--list"] | ["--remotes", "--list"])
        && args[2..].iter().all(|reference| safe_ref(reference))
}

fn line_number(value: &str) -> Option<u64> {
    (value.len() <= 6 && all_ascii_digits(value) && !value.starts_with('0'))
        .then(|| saturating_number(value))
}

pub(crate) fn safe_blame_args(args: &[&str]) -> bool {
    let [flag, range, separator, path] = args else {
        return false;
    };
    if *flag != "-L" || *separator != "--" {
        return false;
    }
    let Some((start, end)) = range.split_once(',') else {
        return false;
    };
    let (Some(start), Some(end)) = (line_number(start), line_number(end)) else {
        return false;
    };
    start <= end && end <= 100_000 && end - start <= 1000 && safe_repository_path(path)
}

fn safe_diff_pathspec(value: &str) -> bool {
    safe_repository_path(value)
        || value
            .strip_prefix(":!")
            .or_else(|| value.strip_prefix(":^"))
            .is_some_and(safe_repository_path)
}

fn safe_diff_revision(arg: &str) -> bool {
    DIFF_WORDS.contains(&arg) || safe_ref(arg)
}

pub(crate) fn safe_diff_args(args: &[&str]) -> bool {
    if args.is_empty() {
        return false;
    }
    let Some(separator) = args.iter().position(|arg| *arg == "--") else {
        return args.iter().all(|arg| safe_diff_revision(arg));
    };
    let (revisions, paths) = (&args[..separator], &args[separator + 1..]);
    !paths.is_empty()
        && revisions.iter().all(|arg| safe_diff_revision(arg))
        && paths.iter().all(|path| safe_diff_pathspec(path))
}

fn safe_object_path(value: &str) -> bool {
    if value.matches(':').count() != 1 {
        return false;
    }
    value
        .split_once(':')
        .is_some_and(|(revision, path)| safe_ref(revision) && safe_repository_path(path))
}

pub(crate) fn safe_show_args(args: &[&str]) -> bool {
    if args.is_empty() {
        return false;
    }
    let Some(separator) = args.iter().position(|arg| *arg == "--") else {
        return args.iter().all(|arg| {
            SHOW_OPTIONS.contains(arg) || *arg == "HEAD" || safe_ref(arg) || safe_object_path(arg)
        });
    };
    let (revisions, paths) = (&args[..separator], &args[separator + 1..]);
    let refs: Vec<&str> = revisions
        .iter()
        .copied()
        .filter(|arg| !SHOW_OPTIONS.contains(arg))
        .collect();
    !paths.is_empty()
        && refs.len() == 1
        && (refs[0] == "HEAD" || safe_ref(refs[0]))
        && revisions
            .iter()
            .all(|arg| SHOW_OPTIONS.contains(arg) || refs.contains(arg))
        && paths.iter().all(|path| safe_repository_path(path))
}

pub(crate) fn safe_ls_files_args(args: &[&str]) -> bool {
    let unique = args
        .iter()
        .enumerate()
        .all(|(index, arg)| !args[..index].contains(arg));
    !args.is_empty()
        && unique
        && args
            .iter()
            .all(|arg| matches!(*arg, "--exclude-standard" | "--others"))
        && args.contains(&"--others")
}

/// Drop the two safe stderr redirects (at most one); any other redirection
/// marker makes the token list unusable.
pub(crate) fn without_stderr_merge(tokens: &[String]) -> Option<Vec<&str>> {
    let is_safe = |token: &str| matches!(token, "2>&1" | "2>/dev/null");
    if tokens.iter().filter(|token| is_safe(token)).count() > 1 {
        return None;
    }
    if tokens
        .iter()
        .any(|token| (token.contains('>') || token.contains('<')) && !is_safe(token))
    {
        return None;
    }
    Some(
        tokens
            .iter()
            .map(String::as_str)
            .filter(|token| !is_safe(token))
            .collect(),
    )
}
