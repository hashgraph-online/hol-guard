//! Read-only `find` expressions.
//!
//! `find` only prints names unless an action predicate runs a program, writes
//! a file, or deletes. Every operand before the expression must be a bounded
//! directory, and the expression may use only matching, depth and print
//! predicates. Actions (`-exec*`, `-ok*`, `-delete`, `-fprint*`, `-fls`,
//! `-printf`), link-following options (`-L`, `-H`, `-follow`) and anything
//! unrecognised keep review. Skill directories and `~/.agents` may be roots
//! because the expression prints names, never contents. The Oh My Pi
//! `~/.agent` root may be one when its tree clears the walk `ls -R` needs.
//! Another home dot-directory may be one when `-maxdepth 1` keeps the walk to
//! its own entries, or when the expression prints only the paths an ordinary
//! name pattern selects.

use super::safe_reads::{bounded_read_target, verified_path_context};

const MAX_FIND_DEPTH: u8 = 32;
const MAX_FIND_ROOTS: usize = 8;
const MAX_PATTERN_BYTES: usize = 256;

pub(super) fn safe_find_listing_arguments(
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let arguments = arguments
        .strip_prefix(&["-P".to_owned()])
        .unwrap_or(arguments);
    let roots_end = arguments
        .iter()
        .position(|argument| argument.starts_with('-') || matches!(argument.as_str(), "!" | "("))
        .unwrap_or(arguments.len());
    let (roots, expression) = arguments.split_at(roots_end);
    if roots.is_empty() || roots.len() > MAX_FIND_ROOTS {
        return false;
    }
    verified_path_context(context.home_dir, context.cwd)
        && arguments
            .iter()
            .all(|argument| super::brace_words::stays_one_word(argument))
        && roots.iter().all(|root| {
            !super::search::skill_link_resolves_over_home(root, context)
                && (bounded_read_target(root, context.home_dir, context.cwd, true)
                    || super::search::skill_listing_root(root, context)
                    || super::search::agent_root_listing(root, context, true)
                    || (entries_only(expression)
                        && super::read_paths::home_hidden_directory(
                            root,
                            context.home_dir,
                            context.cwd,
                        ))
                    || (match_bounded(expression)
                        && super::read_paths::home_hidden_tool_directory(
                            root,
                            context.home_dir,
                            context.cwd,
                        )))
        })
        && safe_expression(expression)
}

/// `-maxdepth 0` or `1` bounds `find` to the root and its own entries, the
/// names a plain `ls` prints. Every `-maxdepth` must say so; deeper values
/// would reach stores nested below a home dot-directory.
fn entries_only(expression: &[String]) -> bool {
    let mut bounded = false;
    let mut index = 0;
    while index < expression.len() {
        let token = expression[index].as_str();
        index += 1;
        match token {
            "-maxdepth" => match expression.get(index).map(String::as_str) {
                Some("0" | "1") => {
                    bounded = true;
                    index += 1;
                }
                _ => return false,
            },
            "-name" | "-iname" | "-path" | "-ipath" | "-wholename" | "-iwholename" | "-type"
            | "-mindepth" => index += 1,
            _ => {}
        }
    }
    bounded
}

/// Whether the expression prints only the paths a name pattern selects.
///
/// `find` walks whatever its root holds, but what it prints is what the
/// expression matches, and the depth bound is there for what a deeper walk
/// would print rather than for the walking itself. A conjunction of `-name`
/// patterns, none of which can name a credential store or the file a tool
/// keeps its own login in, bounds the output to paths that name no account,
/// host or key, however deep the walk goes: `find ~/.agents -maxdepth 4
/// -name pr-approve-merge.sh` can print nothing else.
///
/// Alternation and negation both widen the output back to the whole tree
/// (`-not -name '*.md'` prints everything else), so the expression must be a
/// plain conjunction, and it must carry at least one pattern: an expression
/// that only bounds depth or type still enumerates the tree. `-path` and its
/// spellings match the whole path rather than the entry name, so a directory
/// prefix alone satisfies them and they bound nothing here.
fn match_bounded(expression: &[String]) -> bool {
    let mut bounded = false;
    let mut index = 0;
    while index < expression.len() {
        let token = expression[index].as_str();
        index += 1;
        match token {
            "!" | "-not" | "-o" | "-or" | "(" | ")" | "-path" | "-ipath" | "-wholename"
            | "-iwholename" => return false,
            "-name" | "-iname" => {
                let Some(pattern) = expression.get(index) else {
                    return false;
                };
                index += 1;
                if !selects_ordinary_names(pattern) {
                    return false;
                }
                bounded = true;
            }
            // `find` evaluates left to right, so a print that runs before the
            // first pattern prints every entry the walk reaches and the
            // pattern after it filters nothing:
            // `find ~/.codex -print -name run.sh` prints the whole tree.
            "-print" | "-print0" if !bounded => return false,
            "-type" | "-maxdepth" | "-mindepth" => index += 1,
            _ => {}
        }
    }
    bounded
}

/// Names prose is written under. A pattern anchored to one of these ends
/// matches only documents: a token is not written in Markdown, and no
/// credential, key or login file this screen refuses carries such a suffix.
const DOCUMENT_SUFFIXES: [&str; 3] = [".md", ".markdown", ".rst"];

/// Whether `pattern` names entries specifically enough that the walk prints
/// only what the agent already named, and can name nothing a secret is kept
/// in.
///
/// A wildcard stands for whatever the tree happens to hold, so a pattern
/// built around one selects names the agent never wrote: `*.json` prints
/// `auth.json`, `aut*` and `a?th.json` print it too. Deciding which names a
/// glob can reach means deciding it for every secret-bearing spelling, so a
/// glob survives only as a document suffix anchored at the end of the name:
/// `find ~/.codex -name "*.md"` is how an agent finds the notes a harness
/// keeps, and every path it can print is prose. What is left of such a
/// pattern is still read through [`pattern_can_select_secret`], which lets a
/// wildcard stand for the letters it could take, so `cred?ntials*.md` is
/// refused along with the name it spells.
///
/// Without a wildcard the pattern is the name itself, so it is read the way a
/// file name is read: the stems and suffixes a token, key or login file is
/// written under, refused as whole names rather than as letters appearing
/// somewhere, which is what keeps `keyboard` a name and not a key. `.env`
/// files are refused wherever the word appears, because an environment file
/// is named for what it holds wherever it sits, and a pattern aimed at a
/// hidden entry is refused outright: that is where a tool keeps its own
/// login.
fn selects_ordinary_names(pattern: &str) -> bool {
    let lowered = pattern.to_ascii_lowercase();
    if lowered.starts_with('.') || lowered.contains(['/', '\\']) || lowered.contains("..") {
        return false;
    }
    if lowered.contains(['*', '?', '[', ']', '{', '}']) {
        return DOCUMENT_SUFFIXES
            .iter()
            .any(|suffix| lowered.ends_with(suffix))
            && !crate::credential_store_names::pattern_can_select_secret(&lowered);
    }
    lowered.chars().count() >= 3
        && !lowered.contains("env")
        && !crate::credential_store_names::secret_bearing_file_name(&lowered)
}

fn safe_expression(expression: &[String]) -> bool {
    let mut depth = 0_usize;
    let mut index = 0;
    while index < expression.len() {
        let token = expression[index].as_str();
        index += 1;
        match token {
            "(" => depth += 1,
            ")" => {
                let Some(next) = depth.checked_sub(1) else {
                    return false;
                };
                depth = next;
            }
            "!" | "-not" | "-a" | "-and" | "-o" | "-or" | "-print" | "-print0" | "-prune" => {}
            "-name" | "-iname" | "-path" | "-ipath" | "-wholename" | "-iwholename" => {
                let Some(pattern) = expression.get(index) else {
                    return false;
                };
                if pattern.len() > MAX_PATTERN_BYTES || pattern.contains(['\n', '\r', '\0']) {
                    return false;
                }
                index += 1;
            }
            "-type" => {
                let Some(kind) = expression.get(index) else {
                    return false;
                };
                if !matches!(kind.as_str(), "d" | "f" | "l") {
                    return false;
                }
                index += 1;
            }
            "-maxdepth" | "-mindepth" => {
                let Some(value) = expression.get(index) else {
                    return false;
                };
                if !value.bytes().all(|byte| byte.is_ascii_digit())
                    || !value
                        .parse::<u8>()
                        .is_ok_and(|count| count <= MAX_FIND_DEPTH)
                {
                    return false;
                }
                index += 1;
            }
            _ => return false,
        }
    }
    depth == 0
}
