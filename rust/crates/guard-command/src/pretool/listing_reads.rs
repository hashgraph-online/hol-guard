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
            // A listing without a glob admits a name that is not there, because
            // the shell prints an error and nothing else. One glob beside it
            // does not change what that name prints, so it keeps the same
            // admission: `ls pkg/bun.lock* pkg/package-lock.json` is how an
            // agent asks which lockfile a project keeps.
            Operand::Plain => {
                surviving += 1;
                safe_reads::bounded_read_target(argument, context.home_dir, context.cwd, true)
                    || absent_listing_operand(argument, context)
            }
            Operand::QuotedLiteral => {
                surviving += 1;
                search::safe_literal_bracket_tree(argument, context, recursive)
            }
            Operand::Glob if search::safe_glob_operand(argument, context, recursive) => {
                surviving += 1;
                true
            }
            Operand::Glob => {
                search::safe_unmatched_glob_operand(argument, context, recursive)
                    || (!recursive && leaf_glob_operand(argument, context))
            }
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
    let Some(expanded) = expanded_path(value, context) else {
        return false;
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
                        // `.github` holds a project's workflows, never a
                        // credential, so a probe for them may name it anywhere.
                        !name.starts_with('.')
                            || (index == 0 && name == ".git")
                            || name == ".github"
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

/// The path an operand names, with `~` and a relative cwd resolved.
fn expanded_path(value: &str, context: super::PathContext<'_>) -> Option<std::path::PathBuf> {
    if value.starts_with('~') {
        super::read_paths::expand_home_read_path(value, context.home_dir)
            .map(std::path::PathBuf::from)
    } else if std::path::Path::new(value).is_absolute() {
        Some(std::path::PathBuf::from(value))
    } else {
        let cwd = context.cwd.map(|cwd| {
            super::read_paths::expand_home_read_path(cwd, context.home_dir)
                .unwrap_or_else(|| cwd.to_owned())
        })?;
        Some(std::path::Path::new(&cwd).join(value))
    }
}

/// Upper bound on the entries a leaf glob's directory may hold.
const MAX_LEAF_ENTRIES: usize = 4096;

/// `ls /tmp/.s.PGSQL*`: a pattern in the last component only, below a literal
/// directory that `ls` may list by name. The screened glob expansion refuses
/// hidden and socket matches, but a listing prints only their names, as
/// listing the directory itself would. Every entry the pattern could match
/// under any shell option (`dotglob`, `nocaseglob`) is screened: a directory
/// match has its entries listed, so it needs the listing proof itself, and
/// any other match must clear the sensitive-path and credential-name screens.
fn leaf_glob_operand(value: &str, context: super::PathContext<'_>) -> bool {
    // Windows spells the home path with `\`, so there it is a separator.
    let separator = |c: char| c == '/' || (c == '\\' && cfg!(windows));
    let Some((directory, pattern)) = value.rsplit_once(separator) else {
        return false;
    };
    if directory.is_empty()
        || directory.contains(['*', '?', '[', ']'])
        || pattern.is_empty()
        || value.contains(['$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0'])
        || (value.contains('\\') && !cfg!(windows))
        || value.contains(['{', '}', '(', ')', '!'])
        // A trailing wildcard can always spell a credential name, so the
        // pattern only screens its fixed path; every match is screened below.
        || super::sensitive_path_argument(value)
        || super::sensitive_read_path_argument(directory)
        || !safe_reads::safe_listing_arguments(&[directory.to_owned()], context)
    {
        return false;
    }
    // A superset of every match: the literal text before the first wildcard
    // and after the last one, compared without case.
    let lowered = pattern.to_ascii_lowercase();
    let prefix = &lowered[..lowered.find(['*', '?', '[']).unwrap_or(lowered.len())];
    let suffix = &lowered[lowered.rfind(['*', '?', ']']).map_or(0, |at| at + 1)..];
    let candidate = |name: &str| {
        let name = name.to_ascii_lowercase();
        name.len() >= prefix.len() + suffix.len()
            && name.starts_with(prefix)
            && name.ends_with(suffix)
    };
    // `.*` can match `.` and `..`, which name the directory and its parent.
    if candidate(".") || candidate("..") {
        return false;
    }
    let Some(base) = expanded_path(directory, context) else {
        return false;
    };
    let Ok(entries) = std::fs::read_dir(&base) else {
        return false;
    };
    let mut seen = 0_usize;
    for entry in entries {
        seen += 1;
        let Some(name) = entry
            .ok()
            .and_then(|entry| entry.file_name().into_string().ok())
        else {
            return false;
        };
        if seen > MAX_LEAF_ENTRIES {
            return false;
        }
        if !candidate(&name) {
            continue;
        }
        let path = base.join(&name);
        let Some(text) = path.to_str() else {
            return false;
        };
        // A hidden directory (`.config`, `.cache`) may hold credentials whose
        // names the listing would print, so a wildcard never reaches into one.
        let listed = if std::fs::metadata(&path).is_ok_and(|metadata| metadata.is_dir()) {
            !name.starts_with('.')
                && safe_reads::safe_listing_arguments(&[text.to_owned()], context)
        } else {
            !super::sensitive_read_path_argument(text)
                && std::fs::canonicalize(&path).is_ok_and(|canonical| {
                    super::read_paths::resolved_location_allowed(
                        &canonical,
                        context.home_dir,
                        context.cwd,
                        false,
                    )
                })
        };
        if !listed {
            return false;
        }
    }
    true
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

#[cfg(test)]
mod tests {
    #[test]
    fn a_leaf_glob_lists_hidden_names_in_a_listable_directory_only() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/listing-leaf-glob")
            .join(std::process::id().to_string());
        let home = root.join("home");
        let project = home.join("work/project");
        let run = home.join("work/run");
        for directory in [
            project.join("src"),
            run.join(".cache-x"),
            run.join("data"),
            home.join(".ssh"),
        ] {
            std::fs::create_dir_all(directory).unwrap();
        }
        for file in [
            run.join(".s.PGSQL.5432.lock"),
            run.join(".env"),
            run.join("data/notes.txt"),
            home.join(".ssh/id_rsa"),
        ] {
            std::fs::write(file, "synthetic\n").unwrap();
        }
        let (home, project) = (
            crate::runtime_read_paths::canonicalize_text(&home).unwrap(),
            crate::runtime_read_paths::canonicalize_text(&project).unwrap(),
        );
        let context = crate::pretool::PathContext {
            home_dir: home.to_str(),
            cwd: project.to_str(),
            ..Default::default()
        };
        let w = home.join("work").display().to_string();
        let h = home.display().to_string();
        for (command, allowed) in [
            (format!("ls {w}/run/.s.PGSQL*"), true),
            (
                format!("ls -la {w}/run/.s.PGSQL* {w}/run/.s.MISSING*"),
                true,
            ),
            (format!("ls {w}/run/d*"), true),
            (format!("ls -R {w}/run/.s.PGSQL*"), false),
            (format!("ls {w}/run/.c*"), false),
            (format!("ls {w}/run/.e*"), false),
            (format!("ls {w}/run/.*"), false),
            (format!("ls {w}/*/.s.PGSQL*"), false),
            (format!("ls {h}/.ssh/*"), false),
            (format!("ls {h}/.ssh/id*"), false),
        ] {
            let words: Vec<String> = command.split(' ').map(str::to_owned).collect();
            assert_eq!(
                super::safe_listing_segment(&command, &words[1..], context),
                allowed,
                "{command}"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
