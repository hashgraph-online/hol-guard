//! `ls` operands, including recursion, quoted literals and globs.
//!
//! The parser hands over unquoted words, so a bracket in an argument cannot
//! say whether the shell treats it as a glob. The segment text can: a word
//! whose glob characters are all inside quotes is a literal name (Next.js
//! route directories such as `[slug]`), while an unquoted `*`, `?` or `[` is
//! expanded by the proof itself and every match is checked.

use super::{safe_reads, search};

#[path = "listing_words.rs"]
mod words;
pub(super) use words::literal_words;
use words::quoted_words;

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

/// `absent_recursive` says whether a missing operand stays missing while the
/// listing runs: no peer segment may create a file, directory or link at that
/// name, because a recursive listing walks whatever appears there.
pub(super) fn safe_listing_segment(
    text: &str,
    arguments: &[String],
    context: super::PathContext<'_>,
    absent_recursive: bool,
) -> bool {
    let recursive = arguments.iter().any(|argument| is_recursive_flag(argument));
    let lists_hidden = arguments
        .iter()
        .any(|argument| lists_hidden_entries(argument));
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
            // A name that is not there holds no tree to walk, so a recursive
            // listing of it prints the same error a plain `ls` does. A `~` is
            // expanded by the shell from its own `HOME`, which this screen
            // reads as the declared home, so a walk is admitted under it only
            // once `shell_home_matches` says the two name one directory.
            Operand::Plain if recursive => {
                surviving += 1;
                search::safe_recursive_listing_target(argument, context, lists_hidden)
                    || (absent_recursive
                        && (!argument.starts_with('~') || context.shell_home_matches)
                        && absent_listing_operand(argument, context))
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
    surviving > 0 || !recursive || search::safe_recursive_listing_target(".", context, lists_hidden)
}

/// A glob that a program prints instead of listing, as in `echo src/*`. The
/// shell hands it the names a non-recursive `ls` of the same pattern prints, so
/// the word takes that listing's proof.
pub(super) fn listable_glob(value: &str, context: super::PathContext<'_>) -> bool {
    search::safe_glob_operand(value, context, false)
        || search::safe_unmatched_glob_operand(value, context, false)
        || leaf_glob_operand(value, context)
}

/// `ls` of a path that does not exist prints only an error. Agents probe for
/// optional directories this way (`ls ~/work/scripts 2>/dev/null`). The
/// nearest existing ancestor must be a directory a listing may name, and the
/// path must clear the sensitive screens, so the probe cannot spell a
/// credential location.
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
    if !std::fs::symlink_metadata(&expanded).is_err_and(|error| absent(&error)) {
        return false;
    }
    let mut missing: Vec<&std::ffi::OsStr> = Vec::new();
    for ancestor in expanded.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(_) => {
                let private_temporary =
                    super::listing_temporary::private_temporary_ancestor(ancestor, context);
                // A name that is not there prints `No such file or
                // directory` and nothing else, so what the probe may spell
                // is whatever a listing of the same path would be allowed to
                // print if it did exist. A plain name is one, with the `.git`
                // marker an agent probes for and a repository's `.github`
                // beside it; so is a tool's own directory in the home
                // directory, which a present-path listing already allows and
                // an absent one used to refuse, reporting by the
                // disagreement whether the tool was set up. `~/.aws`,
                // `~/.config/gh` and the other stores stay refused, because
                // the answer to a probe for one of them is itself the
                // account it keeps.
                let spelled = missing.iter().enumerate().all(|(index, part)| {
                    let name = part.to_string_lossy();
                    !name.starts_with('.') || (index == 0 && name == ".git") || name == ".github"
                })
                    || crate::pretool::read_paths::hidden_listing::absent_home_hidden_tool_path(
                        &expanded,
                        ancestor,
                        context.home_dir,
                    )
                    || private_temporary;
                // The owner's private temporary root itself (`$TMPDIR`) sits
                // in a location the listing screens deny, but nobody else can
                // put an entry there, so a missing name below it is enough.
                return !missing.is_empty()
                    && spelled
                    && (private_temporary || listable_ancestor(ancestor, context));
            }
            Err(error) if absent(&error) => {
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

/// Whether a lookup failed because the path is not there. A path that runs
/// through a regular file, as `<worktree>/.git/index.lock` does where `.git`
/// is a linked worktree's gitfile, fails with `Not a directory` and prints
/// that error and nothing else, the same as a missing name. The walk still
/// judges that file as the nearest existing ancestor.
fn absent(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

/// The path an operand names, with `~` and a relative cwd resolved.
///
/// A `~` is expanded here from the declared `home_dir`, which is the home the
/// shell reports; where a caller needs the two to be one directory it screens
/// `shell_home_matches` itself before admitting the operand.
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

/// `ls /tmp/pg-run/.s.PGSQL*`: a pattern in the last component only, below a
/// literal directory that `ls` may list by name and that no other user can
/// add an entry to. The screened glob expansion refuses
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
    // The shell expands the pattern after this screen, and anyone can add a
    // matching link to a world-writable directory (`/tmp`) in between, so a
    // pattern directly below one keeps its review whatever it matches now.
    if super::listing_temporary::writable_by_anyone(&base) {
        return false;
    }
    // The listing names the matches, not the directory holding them, so a
    // temporary directory only the owner can add entries to answers for a
    // pattern below it (`ls /tmp/tmp.ab12/pg*`) although listing it whole
    // may stay reviewed. Every match is screened on its own below.
    if !safe_reads::safe_listing_arguments(&[directory.to_owned()], context)
        && !super::listing_temporary::temporary_glob_directory(&base, context)
    {
        return false;
    }
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
/// by its canonical directory, never by its lexical text. A repository's own
/// Git directory, such as `.git/worktrees/<name>` or a linked worktree's
/// `.git` file, counts too: a listing of it is already allowed, so a probe for
/// `index.lock` or `MERGE_HEAD` below it says no more than that listing. Other
/// hidden directories, such as a package store under `node_modules`, do not.
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
            || (!parent_steps && search::skill_listing_root(parent, context, false))
            || (!parent_steps
                && std::fs::canonicalize(&resolved).is_ok_and(|target| {
                    target.components().any(|part| part.as_os_str() == ".git")
                })
                && super::read_paths::repository_hidden_directory(
                    parent,
                    context.home_dir,
                    context.cwd,
                ))
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

/// `ls` prints a hidden entry only when asked for one. Without `-a`, `-A`,
/// `-f` or their long spellings it neither prints a hidden name nor descends
/// into a hidden directory, so nothing hidden below the root reaches its
/// output.
fn lists_hidden_entries(argument: &str) -> bool {
    if let Some(name) = argument.strip_prefix("--") {
        let name = name.split('=').next().unwrap_or(name);
        return !name.is_empty() && ("all".starts_with(name) || "almost-all".starts_with(name));
    }
    if crate::powershell_reads::windows_powershell_host() && powershell_hidden(argument) {
        return true;
    }
    // GNU `ls -f` is `-aU`: it prints hidden names and descends into hidden
    // directories, so it asks for the same reach `-a` does.
    argument.starts_with('-')
        && argument
            .chars()
            .skip(1)
            .any(|flag| flag == 'a' || flag == 'A' || flag == 'f')
}

/// On Windows `ls` can be PowerShell's Get-ChildItem, where `-Force` is what
/// lists a hidden entry. Any case-insensitive prefix of it counts.
fn powershell_hidden(argument: &str) -> bool {
    argument
        .strip_prefix('-')
        .filter(|name| !name.starts_with('-'))
        .is_some_and(|name| {
            let name = name.split(':').next().unwrap_or(name).to_ascii_lowercase();
            !name.is_empty() && "force".starts_with(name.as_str())
        })
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
#[path = "listing_reads_tests.rs"]
mod tests;
