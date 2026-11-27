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
//!
//! The walk does not reproduce ripgrep's ignore precedence. Wherever it is
//! unsure, it answers "keeps review": any rule that excludes a file counts even
//! if another puts it back, and an ignore file or directory it cannot read in
//! full, a search after `cd`, or a path deeper than it looks all keep review.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::rc::Rc;

#[cfg(test)]
#[path = "workspace_contained_search_widening_walk_tests.rs"]
mod walk_tests;

/// How many directory entries the hidden-entry walk may read. A tree larger
/// than this cannot be answered before the command runs, so it keeps review.
const MAX_INSPECTED: usize = 20_000;

/// The most of one ignore file the walk reads; a larger one keeps review.
const MAX_IGNORE_LINES: usize = 1_024;
const MAX_IGNORE_BYTES: u64 = 64 * 1024;
/// Parent directories searched for ignore files and the repository top.
const MAX_ANCESTORS: usize = 32;

/// A name no real entry has, standing for "anything inside this directory".
const INSIDE: &str = "\u{1}";

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
    // After a directory change the search runs from somewhere this check does
    // not follow, so its globs and roots cannot be read against `cwd`.
    let mut moved = false;
    model.segments.iter().any(|segment| {
        let Some(name) = segment
            .executable
            .as_deref()
            .and_then(|executable| executable.rsplit('/').next())
        else {
            return false;
        };
        if matches!(name, "cd" | "pushd" | "popd") {
            moved = true;
            return false;
        }
        name == "rg" && segment_widens(&segment.arguments, cwd, moved)
    })
}

struct Inclusion {
    text: String,
    ignore_case: bool,
}

fn segment_widens(arguments: &[String], cwd: &Path, moved: bool) -> bool {
    let mut globs = Vec::new();
    let mut positionals = Vec::new();
    let mut fold_case = false;
    // Set when the pattern comes from a flag, or there is none: every
    // positional is then a path.
    let mut pattern_from_flag = false;
    // A `--` that a flag takes as its value (`--context-separator --`) is
    // consumed with that flag; one left standing ends the options.
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            positionals.extend(arguments.by_ref().map(String::as_str));
            break;
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
            match name {
                "glob-case-insensitive" => fold_case = true,
                "no-glob-case-insensitive" => fold_case = false,
                _ => {}
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
    // An exclusion glob only removes files from the search; ignoring it can
    // only make the walk find more.
    let inclusions: Vec<Inclusion> = globs
        .into_iter()
        .filter(|(text, _)| !text.starts_with('!'))
        .map(|(text, ignore_case)| Inclusion {
            text,
            ignore_case: ignore_case || fold_case,
        })
        .collect();
    if inclusions.is_empty() {
        return false;
    }
    if moved {
        return true;
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
    let mut pending = Vec::new();
    for root in roots {
        // A repository top or ignore file beyond the ancestor budget would go unread.
        if root.ancestors().nth(MAX_ANCESTORS).is_some() {
            return true;
        }
        let Some(rules) = ancestor_rules(root) else {
            return true;
        };
        pending.push(Pending {
            directory: root.clone(),
            hidden: false,
            ignored: false,
            matched: false,
            in_repository: in_repository(root),
            rules: Rc::new(rules),
        });
    }
    while let Some(current) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&current.directory) else {
            return true;
        };
        let Some(local) = IgnoreFile::read(&current.directory, current.in_repository) else {
            return true;
        };
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
                let hits = RuleHits::of(&rules, &path, &name, true);
                // A directory is pruned only when a rule excludes it and none
                // puts it back or could not be read, so the walk reads more
                // rather than less. A hidden or pruned directory is entered
                // only when a glob names it or could name something inside it.
                let pruned = hits.excluded && !hits.kept && !hits.unreadable;
                if (name.starts_with('.') || pruned)
                    && !matched
                    && !included(&path.join(INSIDE), INSIDE, cwd, inclusions)
                {
                    continue;
                }
                pending.push(Pending {
                    directory: path,
                    hidden,
                    ignored: current.ignored || hits.excluded || hits.unreadable,
                    matched,
                    in_repository: current.in_repository,
                    rules: Rc::clone(&rules),
                });
            } else if matched
                && (hidden || current.ignored || {
                    // Any rule excluding the file counts, even one another rule
                    // overrides, and so does a rule this walk cannot read.
                    let hits = RuleHits::of(&rules, &path, &name, false);
                    hits.excluded || hits.unreadable
                })
            {
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
    /// Some rule here reads the path from `base`, not just the name.
    reads_paths: bool,
}

impl IgnoreFile {
    /// `None` when an ignore file here cannot be read in full.
    fn read(directory: &Path, in_repository: bool) -> Option<Self> {
        let mut names = Vec::new();
        if in_repository {
            if directory.join(".git").is_dir() {
                names.push(".git/info/exclude");
            }
            names.push(".gitignore");
        }
        names.extend([".ignore", ".rgignore"]);
        let mut rules = Vec::new();
        for name in names {
            if let Some(text) = read_bounded(&directory.join(name))? {
                if text.lines().nth(MAX_IGNORE_LINES).is_some() {
                    return None;
                }
                rules.extend(text.lines().filter_map(Rule::parse));
            }
        }
        Some(Self {
            base: directory.to_path_buf(),
            reads_paths: rules.iter().any(|rule| rule.anchored),
            rules,
        })
    }

    /// The entry's `/`-separated path from this file's directory, worked out
    /// once for all of its rules; `None` when it cannot be read.
    fn relative(&self, path: &Path) -> Option<String> {
        Some(
            path.strip_prefix(&self.base)
                .ok()?
                .to_str()?
                .replace('\\', "/"),
        )
    }
}

/// The text of a small regular file: `Some(None)` when there is no file,
/// `None` when it exists but cannot be read in full without blocking.
fn read_bounded(path: &Path) -> Option<Option<String>> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Some(None);
        }
        Err(_) => return None,
    };
    if !metadata.is_file() || metadata.len() > MAX_IGNORE_BYTES {
        return None;
    }
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_IGNORE_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    (text.len() as u64 <= MAX_IGNORE_BYTES).then_some(Some(text))
}

/// One gitignore line.
struct Rule {
    pattern: String,
    negated: bool,
    /// Matched against the path from the ignore file's directory, not the name.
    anchored: bool,
    directory_only: bool,
    /// The pattern has no wildcard, so it matches only the text equal to it.
    literal: bool,
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
            literal: crate::pretool::search_scope_glob::is_literal(pattern),
        })
    }

    /// `None` when the rule cannot be read for this entry. `relative` is the
    /// entry's path from the ignore file's directory.
    fn matches(&self, relative: Option<&str>, name: &str, is_dir: bool) -> Option<bool> {
        if self.directory_only && !is_dir {
            return Some(false);
        }
        let subject = if self.anchored { relative? } else { name };
        // Most ignore lines name one directory or file outright. The glob
        // matcher would compare them byte by byte, so compare them directly:
        // a walk asks every rule about every entry it meets.
        if self.literal {
            return Some(self.pattern == subject);
        }
        #[cfg(test)]
        GLOB_RULE_READS.with(|reads| reads.set(reads.get() + 1));
        crate::pretool::search_scope_glob::glob_matches(&self.pattern, subject).ok()
    }
}

#[cfg(test)]
thread_local! {
    /// How many times a rule went to the glob matcher on this thread.
    pub(super) static GLOB_RULE_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How the rules of every ignore file that applies meet one entry.
#[derive(Default)]
struct RuleHits {
    /// Some rule excludes it.
    excluded: bool,
    /// Some `!` rule puts it back.
    kept: bool,
    /// Some rule could not be read for it.
    unreadable: bool,
}

impl RuleHits {
    fn of(files: &[Rc<IgnoreFile>], path: &Path, name: &str, is_dir: bool) -> Self {
        let mut hits = Self::default();
        for file in files {
            let relative = if file.reads_paths {
                file.relative(path)
            } else {
                None
            };
            for rule in &file.rules {
                match rule.matches(relative.as_deref(), name, is_dir) {
                    Some(true) if rule.negated => hits.kept = true,
                    Some(true) => hits.excluded = true,
                    Some(false) => {}
                    None => hits.unreadable = true,
                }
            }
        }
        hits
    }
}

fn in_repository(root: &Path) -> bool {
    root.ancestors()
        .take(MAX_ANCESTORS)
        .any(|ancestor| ancestor.join(".git").exists())
}

/// The ignore files in the directories above `root` that ripgrep also reads:
/// git's up to the repository top, `.ignore` and `.rgignore` above it too.
/// `None` when one of them cannot be read in full.
fn ancestor_rules(root: &Path) -> Option<Vec<Rc<IgnoreFile>>> {
    // A root that is a repository top reads no git rules from above it.
    let mut inside = !root.join(".git").exists() && in_repository(root);
    let mut files = Vec::new();
    for ancestor in root.ancestors().skip(1).take(MAX_ANCESTORS) {
        let reads_git_rules = inside;
        if inside && ancestor.join(".git").exists() {
            inside = false;
        }
        let file = IgnoreFile::read(ancestor, reads_git_rules)?;
        if !file.rules.is_empty() {
            files.push(Rc::new(file));
        }
    }
    files.reverse();
    Some(files)
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
