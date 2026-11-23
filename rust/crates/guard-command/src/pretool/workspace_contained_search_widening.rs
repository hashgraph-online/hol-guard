//! A search told to look past ignore rules stays at review.
//!
//! `rg` skips hidden and ignored files unless a glob override (`--glob`,
//! `--iglob`), `--hidden`, `--no-ignore` or `-u` widens it. Those are the
//! files a repository keeps its local secrets in, and the read review stops
//! these searches because it cannot prove what they reach. The sandbox
//! withholds only a fixed list of credential paths, so a contained run would
//! still read a secret kept under any other name and print it.
//!
//! An inclusion glob is the common case: `rg --files -g '*.md'` is how agents
//! list files. ripgrep lets a whitelisting glob bring back a hidden or ignored
//! file, so a glob keeps the review only when the search roots hold such a
//! file the glob actually brings back. Every other way of widening keeps it
//! outright.

use std::path::{Path, PathBuf};
use std::rc::Rc;

#[cfg(test)]
#[path = "workspace_contained_search_widening_walk_tests.rs"]
mod walk_tests;

/// How many directory entries the hidden-entry walk may read. A tree larger
/// than this cannot be answered before the command runs, so it keeps review.
const MAX_INSPECTED: usize = 20_000;

/// Lines read from one ignore file, and parent directories searched for them.
const MAX_IGNORE_LINES: usize = 1_024;
const MAX_ANCESTORS: usize = 32;

/// A name no real entry has, standing for "anything inside this directory".
const INSIDE: &str = "\u{1}";

/// Dotfiles a repository commits for its tools; none of them holds a secret.
const TOOL_DOTFILES: &[&str] = &[
    ".gitignore",
    ".gitattributes",
    ".gitkeep",
    ".keep",
    ".ignore",
    ".rgignore",
];

/// Short flags that take a value, in the same argument or the next one.
const SHORT_WITH_VALUE: &str = "ABCdEefgjMmrtT";

/// Long flags that take a value when it is not given with `=`.
const LONG_WITH_VALUE: &[&str] = &[
    "after-context",
    "before-context",
    "color",
    "colors",
    "context",
    "context-separator",
    "dfa-size-limit",
    "encoding",
    "engine",
    "field-context-separator",
    "field-match-separator",
    "file",
    "generate",
    "glob",
    "hostname-bin",
    "hyperlink-format",
    "iglob",
    "ignore-file",
    "max-columns",
    "max-count",
    "max-depth",
    "maxdepth",
    "max-filesize",
    "path-separator",
    "pre",
    "pre-glob",
    "regex-size-limit",
    "regexp",
    "replace",
    "sort",
    "sortr",
    "threads",
    "type",
    "type-add",
    "type-clear",
    "type-not",
];

/// Whether a segment runs `rg` so that it reaches hidden or ignored files.
/// `cwd` is the directory the command's relative paths resolve against.
pub(super) fn widens_past_ignore_rules(model: &crate::CanonicalCommandV1, cwd: &Path) -> bool {
    model.segments.iter().any(|segment| {
        let Some(executable) = segment.executable.as_deref() else {
            return false;
        };
        executable.rsplit('/').next() == Some("rg") && segment_widens(&segment.arguments, cwd)
    })
}

struct Inclusion {
    text: String,
    ignore_case: bool,
}

fn segment_widens(arguments: &[String], cwd: &Path) -> bool {
    let mut globs = Vec::new();
    let mut positionals = Vec::new();
    // Set when the pattern comes from a flag, or there is none: every
    // positional is then a path.
    let mut pattern_from_flag = false;
    // `--` is not read as the end of options: `--context-separator --` takes
    // it as a value, so a flag after it may still be live.
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            continue;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value.to_owned())),
                None => (long, None),
            };
            if matches!(name, "hidden" | "unrestricted" | "follow") || name.starts_with("no-ignore")
            {
                return true;
            }
            if matches!(name, "files" | "file" | "regexp" | "type-list") {
                pattern_from_flag = true;
            }
            if value.is_none() && !LONG_WITH_VALUE.contains(&name) {
                continue;
            }
            let Some(value) = value.or_else(|| arguments.next().cloned()) else {
                return true;
            };
            if matches!(name, "glob" | "iglob") {
                globs.push((value, name == "iglob"));
            }
        } else if let Some(letters) = argument
            .strip_prefix('-')
            .filter(|letters| !letters.is_empty())
        {
            // A short bundle such as `-nu` or `-g*.ts`; the letters after the
            // first flag that takes a value are that value.
            for (index, letter) in letters.char_indices() {
                if matches!(letter, 'u' | '.' | 'L') {
                    return true;
                }
                if !SHORT_WITH_VALUE.contains(letter) {
                    continue;
                }
                let rest = &letters[index + letter.len_utf8()..];
                let value = if rest.is_empty() {
                    match arguments.next() {
                        Some(value) => value.clone(),
                        None => return true,
                    }
                } else {
                    rest.to_owned()
                };
                match letter {
                    'e' | 'f' => pattern_from_flag = true,
                    'g' => globs.push((value, false)),
                    _ => {}
                }
                break;
            }
        } else {
            positionals.push(argument.as_str());
        }
    }
    // An exclusion glob only removes files from the search.
    let inclusions: Vec<Inclusion> = globs
        .into_iter()
        .filter(|(text, _)| !text.starts_with('!'))
        .map(|(text, ignore_case)| Inclusion { text, ignore_case })
        .collect();
    if inclusions.is_empty() {
        return false;
    }
    // Without a pattern flag the first positional is the pattern, even when
    // it names a directory. With no directory to search, ripgrep searches `cwd`.
    let paths = if pattern_from_flag {
        &positionals[..]
    } else {
        positionals.get(1..).unwrap_or(&[])
    };
    let mut roots: Vec<PathBuf> = paths
        .iter()
        .map(|operand| cwd.join(operand))
        .filter(|path| std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()))
        .collect();
    if roots.is_empty() {
        roots.push(cwd.to_path_buf());
    }
    brings_back_hidden_entry(&roots, cwd, &inclusions)
}

/// Whether walking `roots` the way ripgrep does with these inclusion globs
/// reaches a file its ignore rules would otherwise skip: a hidden file, a file
/// inside a hidden directory, or a file an ignore file excludes.
fn brings_back_hidden_entry(roots: &[PathBuf], cwd: &Path, inclusions: &[Inclusion]) -> bool {
    let mut inspected = 0_usize;
    let mut pending: Vec<Pending> = roots
        .iter()
        .map(|root| Pending {
            directory: root.clone(),
            hidden: false,
            ignored: false,
            matched: false,
            in_repository: in_repository(root),
            rules: Rc::new(ancestor_rules(root)),
        })
        .collect();
    while let Some(current) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&current.directory) else {
            continue;
        };
        let local = IgnoreFile::read(&current.directory, current.in_repository);
        let rules = if local.rules.is_empty() {
            Rc::clone(&current.rules)
        } else {
            let mut rules = (*current.rules).clone();
            rules.push(Rc::new(local));
            Rc::new(rules)
        };
        for entry in entries {
            inspected += 1;
            if inspected > MAX_INSPECTED {
                return true;
            }
            let Ok(entry) = entry else {
                return true;
            };
            let Ok(kind) = entry.file_type() else {
                return true;
            };
            // ripgrep does not follow links without `--follow`.
            if kind.is_symlink() {
                continue;
            }
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let hidden = current.hidden || name.starts_with('.');
            let matched = current.matched || included(&path, &name, cwd, inclusions);
            if kind.is_dir() {
                // A rule this walk cannot read prunes nothing, so the walk
                // reads more rather than less.
                let ignored = is_ignored(&rules, &path, &name, true, false);
                // A hidden or ignored directory is entered only when a glob
                // names it or could name something inside it.
                if (name.starts_with('.') || ignored)
                    && !matched
                    && !included(&path.join(INSIDE), INSIDE, cwd, inclusions)
                {
                    continue;
                }
                pending.push(Pending {
                    directory: path,
                    hidden,
                    ignored: current.ignored || ignored,
                    matched,
                    in_repository: current.in_repository,
                    rules: Rc::clone(&rules),
                });
            } else if matched
                && !TOOL_DOTFILES.contains(&name.as_ref())
                && (hidden || current.ignored || is_ignored(&rules, &path, &name, false, true))
            {
                // A rule this walk cannot read counts as excluding the file.
                return true;
            }
        }
    }
    false
}

struct Pending {
    directory: PathBuf,
    /// Inside a hidden directory.
    hidden: bool,
    /// Inside a directory an ignore file excludes.
    ignored: bool,
    /// Inside a directory an inclusion glob names.
    matched: bool,
    /// Inside a git repository, where ripgrep honours `.gitignore`.
    in_repository: bool,
    /// The ignore files that apply here, outermost first.
    rules: Rc<Vec<Rc<IgnoreFile>>>,
}

/// The rules of the ignore files in one directory, in rising precedence:
/// `.git/info/exclude` and `.gitignore` inside a repository, then `.ignore`
/// and `.rgignore`, which ripgrep reads everywhere.
struct IgnoreFile {
    base: PathBuf,
    rules: Vec<Rule>,
}

impl IgnoreFile {
    fn read(directory: &Path, in_repository: bool) -> Self {
        let mut names = Vec::new();
        if in_repository {
            names.extend([".git/info/exclude", ".gitignore"]);
        }
        names.extend([".ignore", ".rgignore"]);
        let rules = names
            .into_iter()
            .filter_map(|name| std::fs::read_to_string(directory.join(name)).ok())
            .flat_map(|text| {
                text.lines()
                    .take(MAX_IGNORE_LINES)
                    .filter_map(Rule::parse)
                    .collect::<Vec<_>>()
            })
            .collect();
        Self {
            base: directory.to_path_buf(),
            rules,
        }
    }
}

/// One gitignore line.
struct Rule {
    pattern: String,
    negated: bool,
    /// Matched against the path from the ignore file's directory, not the name.
    anchored: bool,
    directory_only: bool,
}

impl Rule {
    fn parse(line: &str) -> Option<Self> {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let (negated, rule) = match line.strip_prefix('!') {
            Some(rule) => (true, rule),
            None => (false, line),
        };
        let rule = rule.strip_prefix('\\').unwrap_or(rule);
        let directory_only = rule.ends_with('/');
        let rule = rule.trim_end_matches('/');
        let anchored = rule.contains('/');
        let pattern = rule.trim_start_matches('/');
        if pattern.is_empty() {
            return None;
        }
        Some(Self {
            pattern: pattern.to_owned(),
            negated,
            anchored,
            directory_only,
        })
    }

    /// `None` when the rule cannot be read for this entry.
    fn matches(&self, base: &Path, path: &Path, name: &str, is_dir: bool) -> Option<bool> {
        if self.directory_only && !is_dir {
            return Some(false);
        }
        let subject = if self.anchored {
            path.strip_prefix(base).ok()?.to_str()?.replace('\\', "/")
        } else {
            name.to_owned()
        };
        crate::pretool::search_scope_glob::glob_matches(&self.pattern, &subject).ok()
    }
}

/// Whether the ignore files that apply exclude this entry. The deepest file
/// decides, and within a file the last matching line; `unreadable` is the
/// answer when a rule cannot be read.
fn is_ignored(
    files: &[Rc<IgnoreFile>],
    path: &Path,
    name: &str,
    is_dir: bool,
    unreadable: bool,
) -> bool {
    for file in files.iter().rev() {
        for rule in file.rules.iter().rev() {
            match rule.matches(&file.base, path, name, is_dir) {
                Some(true) => return !rule.negated,
                Some(false) => {}
                None => return unreadable,
            }
        }
    }
    false
}

fn in_repository(root: &Path) -> bool {
    root.ancestors()
        .take(MAX_ANCESTORS)
        .any(|ancestor| ancestor.join(".git").exists())
}

/// The ignore files in the directories above `root` that ripgrep also reads:
/// git's up to the repository top, `.ignore` and `.rgignore` above it too.
fn ancestor_rules(root: &Path) -> Vec<Rc<IgnoreFile>> {
    // A root that is a repository top reads no git rules from above it.
    let mut inside = !root.join(".git").exists() && in_repository(root);
    let mut files = Vec::new();
    for ancestor in root.ancestors().skip(1).take(MAX_ANCESTORS) {
        let reads_git_rules = inside;
        if inside && ancestor.join(".git").exists() {
            inside = false;
        }
        let file = IgnoreFile::read(ancestor, reads_git_rules);
        if !file.rules.is_empty() {
            files.push(Rc::new(file));
        }
    }
    files.reverse();
    files
}

/// Whether one inclusion glob names this entry, read the way ripgrep reads an
/// override: a glob without `/` matches the name at any depth, one with `/`
/// matches the path from the working directory. A glob this matcher cannot
/// read counts as a match.
fn included(path: &Path, name: &str, cwd: &Path, inclusions: &[Inclusion]) -> bool {
    let relative = path
        .strip_prefix(cwd)
        .ok()
        .and_then(|relative| relative.to_str())
        .map(|relative| relative.replace('\\', "/"));
    inclusions.iter().any(|inclusion| {
        let fold = |text: &str| {
            if inclusion.ignore_case {
                text.to_lowercase()
            } else {
                text.to_owned()
            }
        };
        let glob = fold(inclusion.text.trim_start_matches('/').trim_end_matches('/'));
        let Ok(alternatives) = crate::pretool::search_scope_glob::expand_braces(&glob) else {
            return true;
        };
        alternatives.iter().any(|alternative| {
            let subject = if alternative.contains('/') || inclusion.text.starts_with('/') {
                match &relative {
                    Some(relative) => fold(relative),
                    None => return true,
                }
            } else {
                fold(name)
            };
            crate::pretool::search_scope_glob::glob_matches(alternative, &subject).unwrap_or(true)
        })
    })
}
