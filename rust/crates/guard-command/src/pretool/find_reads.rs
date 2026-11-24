//! Read-only `find` expressions.
//!
//! `find` only prints names unless an action predicate runs a program, writes
//! a file, or deletes. Every operand before the expression must be a bounded
//! directory, and the expression may use only matching, depth and print
//! predicates. Actions (`-exec*`, `-ok*`, `-delete`, `-fprint*`, `-fls`, a
//! `-printf` format beyond name directives), link-following options (`-L`,
//! `-H`, `-follow`) and anything unrecognised keep review. Skill directories and `~/.agents` may be roots
//! because the expression prints names, never contents. The Oh My Pi
//! `~/.agent` root may be one when its tree clears the walk `ls -R` needs.
//! Another home dot-directory may be one when `-maxdepth 1` keeps the walk to
//! its own entries, or when the expression prints only the paths an ordinary
//! name pattern selects, whether that pattern is the name itself, a document
//! suffix, or a glob built around a word someone chose.
//! A project-metadata directory such as `.github` in a
//! repository may be one when every entry below it clears the recursive
//! listing screen, and a root that does not exist prints only an error, as
//! the same probe does for `ls`.

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
                    || super::search::skill_listing_root(root, context, true)
                    || super::search::agent_root_listing(root, context, true)
                    || super::search::metadata_directory_walk(root, context)
                    || super::listing_reads::absent_listing_operand(root, context)
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
                        )
                        && (!entries_only_bound(expression)
                            || super::read_paths::home_hidden_walk_clears_stores(
                                root,
                                context.home_dir,
                                context.cwd,
                            ))
                        && (!entries_only_bound(expression)
                            || !selects_links(expression)
                            || super::read_paths::hidden_listing::home_hidden_link_names(
                                root,
                                context.home_dir,
                                context.cwd,
                                walk_depth(expression),
                                selects_ordinary_names,
                            ))))
        })
        && safe_expression(expression, &|reference| reference_file(reference, context))
}

/// Whether this `find` expression writes nothing, wherever its roots are.
///
/// It may hold only the matching, depth and print predicates
/// [`safe_find_listing_arguments`] takes, never an action (`-exec*`, `-ok*`,
/// `-delete`, `-fprint*`, `-fls`). This asks nothing about the roots, which
/// `find` only walks, and a `-newer` reference is read for its time alone.
/// The caller screens redirects and shell expansion
/// (`write_free_steps::writes_nothing`).
pub(super) fn expression_writes_nothing(arguments: &[String]) -> bool {
    let arguments = arguments
        .strip_prefix(&["-P".to_owned()])
        .unwrap_or(arguments);
    let roots_end = arguments
        .iter()
        .position(|argument| argument.starts_with('-') || matches!(argument.as_str(), "!" | "("))
        .unwrap_or(arguments.len());
    let (roots, expression) = arguments.split_at(roots_end);
    !roots.is_empty()
        && roots.len() <= MAX_FIND_ROOTS
        && safe_expression(expression, &|reference| !reference.starts_with('-'))
}

/// Whether `find -newer FILE` may compare against `FILE`. The test reads
/// only that file's modification time, never its bytes, so a file a plain
/// read could open clears it. A missing file, a home dot-directory, a
/// credential store and a path outside the reads Guard proves keep the
/// review.
fn reference_file(reference: &str, context: super::PathContext<'_>) -> bool {
    !reference.starts_with('-')
        && bounded_read_target(reference, context.home_dir, context.cwd, false)
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
            | "-mindepth" | "-printf" => index += 1,
            _ => {}
        }
    }
    bounded
}

/// Whether `-type d` or `-type l` is all that bounds the expression, with no
/// `-name` pattern to decide which paths may be printed.
///
/// `find` evaluates left to right, so a pattern only decides what is printed
/// when it comes before the print: `find ~/.cache/tool -type l -print -name x`
/// prints every link before the pattern is tested, and is bounded by the type
/// alone.
fn entries_only_bound(expression: &[String]) -> bool {
    let mut index = 0;
    while let Some(token) = expression.get(index) {
        index += 1;
        match token.as_str() {
            "-name" | "-iname" => return false,
            "-print" | "-print0" | "-printf" => return true,
            "-type" | "-maxdepth" | "-mindepth" | "-path" | "-ipath" | "-wholename"
            | "-iwholename" => index += 1,
            _ => {}
        }
    }
    true
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
/// plain conjunction, and it must carry at least one pattern. `-path` and its
/// spellings match the whole path rather than the entry name, so a directory
/// prefix alone satisfies them and they bound nothing here. Inside a
/// conjunction they still only narrow what another predicate already bounds:
/// `find ~/.nvm/versions/node -path '*/lib/node_modules/*' -type d` prints a
/// subset of the directories `-type d` alone would, so they are read past
/// rather than refused.
///
/// `-type d` bounds the output the same way without naming anything: it
/// prints directory names and no file, and a secret is a file. The root is
/// already one tool's own directory rather than a shared one, and
/// `find ~/.nvm -maxdepth 2 -type d` is the inventory an agent takes of a
/// toolchain it is about to use. What `-type d` cannot say on its own is
/// that the tree below holds no store, so a walk bounded by nothing else is
/// also screened against the root's own entries by
/// [`super::read_paths::home_hidden_walk_clears_stores`]: a store directly
/// below the root would otherwise have its own layout printed. A `-name`
/// pattern in the same expression already decides what may be printed, so a
/// walk carrying one keeps its existing proof.
///
/// `-type l` bounds it the same way: it prints link names and follows none.
/// Each name it could print is read from the tree itself first, so a link
/// with a hidden or secret-style name, or one inside a store, keeps the
/// review.
fn match_bounded(expression: &[String]) -> bool {
    let mut bounded = false;
    let mut index = 0;
    while index < expression.len() {
        let token = expression[index].as_str();
        index += 1;
        match token {
            "!" | "-not" | "-o" | "-or" | "(" | ")" => return false,
            "-path" | "-ipath" | "-wholename" | "-iwholename" => {
                if expression.get(index).is_none() {
                    return false;
                }
                index += 1;
            }
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
            "-print" | "-print0" | "-printf" if !bounded => return false,
            "-printf" => index += 1,
            "-type" => {
                if matches!(expression.get(index).map(String::as_str), Some("d" | "l")) {
                    bounded = true;
                }
                index += 1;
            }
            "-maxdepth" | "-mindepth" => index += 1,
            _ => {}
        }
    }
    bounded
}

/// Whether the expression selects links. Without a `-name` pattern,
/// `-type l` prints every link name the walk reaches, each of which
/// [`super::read_paths::hidden_listing::home_hidden_link_names`] reads
/// before the walk proceeds.
fn selects_links(expression: &[String]) -> bool {
    expression
        .windows(2)
        .any(|pair| pair[0] == "-type" && pair[1] == "l")
}

/// The deepest level the walk reaches: the largest `-maxdepth`, or `None`
/// when none is given and `find` walks the whole tree.
fn walk_depth(expression: &[String]) -> Option<usize> {
    expression
        .windows(2)
        .filter(|pair| pair[0] == "-maxdepth")
        .filter_map(|pair| pair[1].parse::<usize>().ok())
        .max()
}

/// Names prose is written under. A pattern anchored to one of these ends
/// matches only documents: a token is not written in Markdown, and no
/// credential, key or login file this screen refuses carries such a suffix.
const DOCUMENT_SUFFIXES: [&str; 3] = [".md", ".markdown", ".rst"];

/// How many letters of a glob have to be literal, in one unbroken run, before
/// they name a word someone chose rather than a kind of file. The spellings a
/// kind is written under are shorter than that: `json`, `yaml`, `toml`,
/// `lock`, `conf` are four letters, and the names sessions look their own
/// work up by — `usage-rollup`, `web-client`, `toolchain` — are longer.
const CHOSEN_WORD_LETTERS: usize = 6;

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
        return (DOCUMENT_SUFFIXES
            .iter()
            .any(|suffix| lowered.ends_with(suffix))
            || names_a_chosen_word(&lowered))
            && !crate::credential_store_names::pattern_can_select_secret(&lowered);
    }
    lowered.chars().count() >= 3
        && !lowered.contains("env")
        && !crate::credential_store_names::secret_bearing_file_name(&lowered)
}

/// Whether a glob is built around a word someone chose rather than around the
/// wildcard itself.
///
/// `find ~/.codex -name "*release-notes*"` prints what a session's own notes
/// are called: the literal run is the name, and the wildcards only say the
/// agent does not know what sits either side of it. `*.json` is the opposite
/// shape — the literal run is an extension every file of a kind carries, so
/// what gets printed is whatever the tree happens to hold, `auth.json` among
/// it.
///
/// A run that carries a dot is binding an extension, however long it is:
/// `*h.json` is one letter of a name and a kind, and the names it reaches are
/// the kind's, `auth.json` among them. So the run that counts is an unbroken
/// one with no dot in it, long enough to be a word someone picked. The whole
/// pattern is still read through
/// [`crate::credential_store_names::pattern_can_select_secret`], so a chosen
/// word that spells a store (`*credential-notes*`) is refused with the name
/// it reaches.
///
/// A bracket stands for a set of letters that reading the run cannot see, so
/// `[ac]uth.json` is not read this way and keeps the document-suffix rule.
fn names_a_chosen_word(pattern: &str) -> bool {
    !pattern.contains(['[', ']', '{', '}'])
        && pattern
            .split(['*', '?'])
            .any(|run| run.chars().count() >= CHOSEN_WORD_LETTERS && !run.contains('.'))
}

/// Whether the arguments are roots followed by an expression that only
/// matches, prunes and prints names: no action runs a program, writes a file
/// or deletes. The roots themselves are not checked here.
pub(super) fn prints_names_only(arguments: &[String]) -> bool {
    let arguments = arguments
        .strip_prefix(&["-P".to_owned()])
        .unwrap_or(arguments);
    let roots_end = arguments
        .iter()
        .position(|argument| argument.starts_with('-') || matches!(argument.as_str(), "!" | "("))
        .unwrap_or(arguments.len());
    // `-printf '%f'` drops the root prefix, so a printed name could begin
    // with `-`; callers of this read the output as root-prefixed paths.
    roots_end > 0
        && !arguments[roots_end..]
            .iter()
            .any(|argument| argument == "-printf")
        && safe_expression(&arguments[roots_end..], &|_| false)
}

/// Whether a `-printf` format prints only entry names and paths: literal text,
/// the `\n`, `\0` and `\t` escapes, `%%`, and the `%f`, `%p`, `%P` and `%h`
/// directives with no width or flags.
fn names_only_format(format: &str) -> bool {
    if format.is_empty() || format.len() > MAX_PATTERN_BYTES || format.contains(['\n', '\r', '\0'])
    {
        return false;
    }
    let mut chars = format.chars();
    while let Some(character) = chars.next() {
        match character {
            '%' => {
                if !matches!(chars.next(), Some('f' | 'p' | 'P' | 'h' | '%')) {
                    return false;
                }
            }
            '\\' => {
                if !matches!(chars.next(), Some('n' | '0' | 't')) {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

/// `reference` answers whether a `-newer` operand is a file the walk may
/// compare against; a caller that has no paths to check refuses every one.
fn safe_expression(expression: &[String], reference: &dyn Fn(&str) -> bool) -> bool {
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
            "!" | "-not" | "-a" | "-and" | "-o" | "-or" | "-print" | "-print0" | "-prune"
            | "-empty" => {}
            // Age and size tests compare each entry's own metadata with a
            // number written in the command, so they only narrow which names
            // are printed. `-newer FILE` reads another path's modification
            // time, so that path must pass `reference` first.
            "-newer" => {
                if !expression.get(index).is_some_and(|file| reference(file)) {
                    return false;
                }
                index += 1;
            }
            // `-newerXY`: a reference file passes `reference` like `-newer`'s;
            // `Y` = `t` compares with a date written in the command instead.
            newer if newer_time_test(newer).is_some() => {
                let Some(value) = expression.get(index) else {
                    return false;
                };
                let allowed = if newer_time_test(newer) == Some(true) {
                    written_date(value)
                } else {
                    reference(value)
                };
                if !allowed {
                    return false;
                }
                index += 1;
            }
            // `-printf` writes to standard output like `-print`, and a format
            // made only of name directives prints nothing `-print` would not:
            // `%f` the entry name, `%p` and `%P` its path, `%h` its parent.
            // Every other directive, a link target, owner, size or time among
            // them, keeps the review, as does a format a caller may treat as
            // root-prefixed names (see `prints_names_only`).
            "-printf" => {
                if !expression
                    .get(index)
                    .is_some_and(|format| names_only_format(format))
                {
                    return false;
                }
                index += 1;
            }
            "-mtime" | "-mmin" | "-atime" | "-amin" | "-ctime" | "-cmin" | "-size" => {
                let Some(value) = expression.get(index) else {
                    return false;
                };
                if !metadata_test_value(value, token == "-size") {
                    return false;
                }
                index += 1;
            }
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

/// For a `-newerXY` test, whether `Y` names a written date (`t`) rather than
/// a reference file. `None` when the token is not such a test.
fn newer_time_test(token: &str) -> Option<bool> {
    let times = token.strip_prefix("-newer")?.as_bytes();
    match times {
        [own, other] if b"aBcm".contains(own) && b"aBcmt".contains(other) => Some(*other == b't'),
        _ => None,
    }
}

/// A date `find` parses itself, such as `2026-11-18 17:11` or `1 hour ago`.
fn written_date(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.starts_with('-')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " -:/+.,T".contains(c))
}

/// A `find` age or size operand: an optional `+` or `-`, digits, and for
/// `-size` one unit letter, as in `+1`, `-30` or `+10M`.
fn metadata_test_value(value: &str, size: bool) -> bool {
    let unsigned = value.strip_prefix(['+', '-']).unwrap_or(value);
    let digits = match unsigned.strip_suffix(|unit: char| size && "bckwMGTP".contains(unit)) {
        Some(digits) => digits,
        None => unsigned,
    };
    !digits.is_empty() && digits.len() <= 12 && digits.bytes().all(|byte| byte.is_ascii_digit())
}
