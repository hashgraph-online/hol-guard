//! `ls` operands, including recursion, quoted literals and globs.
//!
//! The parser hands over unquoted words, so a bracket in an argument cannot
//! say whether the shell treats it as a glob. The segment text can: a word
//! whose glob characters are all inside quotes is a literal name (Next.js
//! route directories such as `[slug]`), while an unquoted `*`, `?` or `[` is
//! expanded by the proof itself and every match is checked.

use super::{safe_reads, search};

struct Word {
    value: String,
    unquoted_glob: bool,
    quoted_glob: bool,
}

/// Split segment text into shell words, tracking where glob characters sit.
/// `None` for anything beyond plain words and simple quotes, which makes the
/// caller treat every glob character as unquoted.
fn quoted_words(text: &str) -> Option<Vec<Word>> {
    let mut words = Vec::new();
    let mut current: Option<Word> = None;
    let mut quote: Option<char> = None;
    for character in text.chars() {
        match quote {
            Some(open) if character == open => quote = None,
            Some(open) => {
                if character == '\\' || (open == '"' && matches!(character, '$' | '`')) {
                    return None;
                }
                let word = current.get_or_insert_with(|| Word {
                    value: String::new(),
                    unquoted_glob: false,
                    quoted_glob: false,
                });
                word.quoted_glob |= matches!(character, '*' | '?' | '[');
                word.value.push(character);
            }
            None if matches!(character, '\'' | '"') => {
                quote = Some(character);
                current.get_or_insert_with(|| Word {
                    value: String::new(),
                    unquoted_glob: false,
                    quoted_glob: false,
                });
            }
            None if character == '\\' => return None,
            None if character.is_whitespace() => words.extend(current.take()),
            None => {
                let word = current.get_or_insert_with(|| Word {
                    value: String::new(),
                    unquoted_glob: false,
                    quoted_glob: false,
                });
                word.unquoted_glob |= matches!(character, '*' | '?' | '[');
                word.value.push(character);
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    words.extend(current);
    Some(words)
}

enum Operand {
    Plain,
    QuotedLiteral,
    Glob,
}

fn classify_operands(text: &str, arguments: &[String]) -> Option<Vec<Operand>> {
    let words = quoted_words(text)?;
    let (_, rest) = words.split_first()?;
    if rest.len() != arguments.len()
        || rest
            .iter()
            .zip(arguments)
            .any(|(word, argument)| word.value != *argument)
    {
        return None;
    }
    rest.iter()
        .map(|word| match (word.unquoted_glob, word.quoted_glob) {
            (false, false) => Some(Operand::Plain),
            (false, true) => Some(Operand::QuotedLiteral),
            (true, false) => Some(Operand::Glob),
            (true, true) => None,
        })
        .collect()
}

pub(super) fn safe_listing_segment(
    text: &str,
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let recursive = arguments.iter().any(|argument| is_recursive_flag(argument));
    if !recursive
        && !arguments
            .iter()
            .any(|argument| !argument.starts_with('-') && argument.contains(['*', '?', '[']))
    {
        return safe_reads::safe_listing_arguments(arguments, context);
    }
    if arguments.iter().any(|argument| follows_links(argument)) && recursive {
        return false;
    }
    // Without a trustworthy quote map every glob character counts as unquoted.
    let kinds = classify_operands(text, arguments);
    // `nullglob` removes an unmatched bracket operand. A remaining plain,
    // quoted, or matched operand is what the shell actually lists.
    let mut surviving = 0_usize;
    for (index, argument) in arguments.iter().enumerate() {
        if argument == "-" {
            return false;
        }
        if argument.starts_with('-') {
            continue;
        }
        let kind = match &kinds {
            Some(kinds) => &kinds[index],
            None if argument.contains(['*', '?', '[']) => &Operand::Glob,
            None => &Operand::Plain,
        };
        let allowed = match kind {
            Operand::Plain if recursive => {
                surviving += 1;
                search::safe_recursive_target(argument, context)
            }
            Operand::Plain => {
                surviving += 1;
                safe_reads::bounded_read_target(argument, context.home_dir, context.cwd, true)
            }
            Operand::QuotedLiteral => {
                surviving += 1;
                search::safe_literal_bracket_tree(argument, context, recursive)
            }
            Operand::Glob if search::safe_glob_operand(argument, context, recursive) => {
                surviving += 1;
                true
            }
            Operand::Glob => search::safe_unmatched_glob_operand(argument, context, recursive),
        };
        if !allowed {
            return false;
        }
    }
    // A recursive listing walks the working directory only when no operand
    // survives. An unmatched bracket beside a real operand does not.
    surviving > 0 || !recursive || search::safe_recursive_target(".", context)
}

/// `ls` of a path that does not exist prints only an error. Agents probe for
/// optional directories this way (`ls ~/work/scripts 2>/dev/null`). The
/// nearest existing ancestor must be a directory a listing may name, and every
/// missing component must be a visible name that clears the sensitive screens,
/// so the probe cannot spell a hidden or credential location.
pub(super) fn absent_listing_operand(value: &str, context: super::PathContext<'_>) -> bool {
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('-')
        || value.contains(|c: char| {
            // Windows spells the home path with `\`, so there it is a separator.
            (c == '\\' && !cfg!(windows))
                || [
                    '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '[', ']', '{',
                    '}',
                ]
                .contains(&c)
        })
        || !parent_steps_lead(value)
        || super::sensitive_read_path_argument(value)
        || !safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return false;
    }
    let expanded = if value.starts_with('~') {
        let Some(expanded) = super::read_paths::expand_home_read_path(value, context.home_dir)
        else {
            return false;
        };
        std::path::PathBuf::from(expanded)
    } else if std::path::Path::new(value).is_absolute() {
        std::path::PathBuf::from(value)
    } else {
        let Some(cwd) = context.cwd.and_then(|cwd| {
            super::read_paths::expand_home_read_path(cwd, context.home_dir)
                .or_else(|| Some(cwd.to_owned()))
        }) else {
            return false;
        };
        std::path::Path::new(&cwd).join(value)
    };
    if !std::fs::symlink_metadata(&expanded)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        return false;
    }
    let mut missing: Vec<&std::ffi::OsStr> = Vec::new();
    for ancestor in expanded.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(_) => {
                return !missing.is_empty()
                    && missing.iter().enumerate().all(|(index, part)| {
                        let name = part.to_string_lossy();
                        // `.git` is the one marker agents probe for. A missing
                        // leaf prints only an error and reveals no content.
                        !name.starts_with('.') || (index == 0 && name == ".git")
                    })
                    && listable_ancestor(ancestor, context);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let Some(name) = ancestor.file_name() else {
                    return false;
                };
                missing.push(name);
            }
            Err(_) => return false,
        }
    }
    false
}

/// `..` may only lead a relative operand (`../sibling/missing`). A parent
/// step after any other name, or behind a rooted or `~` spelling, is refused.
fn parent_steps_lead(value: &str) -> bool {
    value
        .split(['/', '\\'])
        .skip_while(|part| *part == "..")
        .all(|part| part != "..")
}

/// The nearest existing ancestor must be a directory a listing may name. The
/// kernel resolves `..` physically, so a spelling with parent steps is judged
/// by its canonical directory, never by its lexical text.
fn listable_ancestor(ancestor: &std::path::Path, context: super::PathContext<'_>) -> bool {
    let parent_steps = ancestor
        .components()
        .any(|component| component == std::path::Component::ParentDir);
    let resolved = if parent_steps {
        match std::fs::canonicalize(ancestor) {
            Ok(canonical) if canonical.is_dir() => canonical,
            _ => return false,
        }
    } else {
        ancestor.to_path_buf()
    };
    resolved.to_str().is_some_and(|parent| {
        safe_reads::bounded_read_target(parent, context.home_dir, context.cwd, true)
            || (!parent_steps && search::skill_listing_root(parent, context))
    })
}

fn is_recursive_flag(argument: &str) -> bool {
    // GNU getopt accepts any unambiguous prefix (`--rec`), so treat them all as recursive.
    argument.strip_prefix("--").is_some_and(|name| {
        name.len() >= 2 && "recursive".starts_with(name.split('=').next().unwrap_or(name))
    }) || (argument.starts_with('-') && !argument.starts_with("--") && argument.contains('R'))
        || (crate::powershell_reads::windows_powershell_host() && powershell_recursion(argument))
}

/// On Windows `ls` can be PowerShell's Get-ChildItem. `-s` is the documented
/// alias of `-Recurse`. Any other case-insensitive prefix of `-Recurse` or
/// `-Depth` (`-rec`, `-depth:2`) is recursive too.
fn powershell_recursion(argument: &str) -> bool {
    let Some(name) = argument
        .strip_prefix('-')
        .filter(|name| !name.starts_with('-'))
    else {
        return false;
    };
    let name = name.split(':').next().unwrap_or(name).to_ascii_lowercase();
    // `s` is Get-ChildItem's documented alias for `-Recurse`.
    name == "s" || (name.len() >= 2 && ("recurse".starts_with(&name) || "depth".starts_with(&name)))
}

fn follows_links(argument: &str) -> bool {
    matches!(
        argument,
        "--dereference"
            | "--dereference-command-line"
            | "--dereference-command-line-symlink-to-dir"
    ) || (argument.starts_with('-') && !argument.starts_with("--") && argument.contains(['L', 'H']))
}
