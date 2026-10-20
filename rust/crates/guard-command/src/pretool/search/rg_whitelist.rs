//! Ignore-file negations that let `rg` reach hidden files.
//!
//! `rg` skips hidden entries on its own, but an entry an ignore rule
//! re-includes is searched even when it is hidden: `!.env` in a `.gitignore`,
//! `.ignore` or `.rgignore`, the repository's `info/exclude` or the global
//! Git excludes file makes a plain `rg foo` print `.env` lines. A content
//! search is proven only when no such rule can re-include a hidden entry
//! that exists below the search root. A negation component is harmless when
//! it is visible, names a benign dotfile such as `.gitkeep`, or is a wildcard
//! that passes the screen `-g` include globs get; any other component counts
//! only if it matches a hidden name the walk finds, so `!.env.example` in a
//! repository without that file does not hold every search.
//!
//! The walk reads only ignore files and names, never other contents. It
//! skips links and hidden directories other than benign ones, which `rg`
//! does not enter, and prunes directories a plain ignore rule names unless
//! some negation re-includes that name.
use super::tree;
use super::ReadContext;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_ENTRIES: usize = 100_000;
const MAX_DEPTH: usize = 64;
const MAX_IGNORE_BYTES: u64 = 64 * 1024;
const IGNORE_FILES: [&str; 3] = [".gitignore", ".ignore", ".rgignore"];

/// Negation components seen so far: every one, for re-entered directories,
/// and the re-included paths that could name a hidden secret.
#[derive(Default)]
struct Negations {
    all: Vec<String>,
    risky: Vec<Risk>,
}

/// One negated pattern, kept with the scope Git gives it.
///
/// A pattern anchored to its ignore file's directory, by a leading slash or
/// by a slash anywhere inside it, re-includes that one path and nothing
/// else: `!/.env.example` at a repository root says nothing about
/// `src/.env.example`, which `rg` keeps skipping as an ordinary hidden
/// entry. A bare name re-includes every entry of that name below the
/// directory the ignore file applies to.
struct Risk {
    /// The directory the ignore file applies to.
    base: PathBuf,
    /// The pattern's components, each with whether it could name a hidden
    /// secret on its own.
    components: Vec<(String, bool)>,
    /// Whether the single component re-includes a name at any depth.
    anywhere: bool,
}

impl Risk {
    /// Whether this negation re-includes `path`, a hidden entry the walk
    /// found, or a directory on the way to one.
    fn re_includes(&self, path: &Path) -> bool {
        let glob = |pattern: &str, name: &std::ffi::OsStr| {
            super::glob_matches(
                pattern.to_ascii_lowercase().as_bytes(),
                name.to_string_lossy().to_ascii_lowercase().as_bytes(),
            )
        };
        let Ok(relative) = path.strip_prefix(&self.base) else {
            return false;
        };
        if self.anywhere {
            let Some((pattern, risky)) = self.components.first() else {
                return false;
            };
            return *risky && relative.file_name().is_some_and(|name| glob(pattern, name));
        }
        // A directory on the way to the re-included path is re-included
        // too, so a prefix of the pattern's components counts, and the
        // component the path ends at decides whether it could name a
        // secret.
        let names: Vec<&std::ffi::OsStr> = relative.iter().collect();
        let Some((_, risky)) = names
            .len()
            .checked_sub(1)
            .and_then(|index| self.components.get(index))
        else {
            return false;
        };
        *risky
            && names
                .iter()
                .copied()
                .zip(&self.components)
                .all(|(name, (pattern, _))| glob(pattern, name))
    }
}

/// A directory a plain ignore rule prunes: a bare name anywhere below the
/// ignore file, or a path a `/` anchors to the ignore file's directory.
#[derive(Clone)]
enum Target {
    Name(String),
    Path(PathBuf),
}

#[derive(Clone)]
struct Rule {
    target: Target,
    /// The rule comes from Git's ignore files, which a nested repository
    /// stops and which apply only inside a repository.
    git: bool,
}

impl Rule {
    fn prunes(&self, path: &Path, name: &str) -> bool {
        // `rg` matches case-sensitively; an exact match prunes no more than
        // it does.
        match &self.target {
            Target::Name(rule) => rule == name,
            Target::Path(rule) => rule == path,
        }
    }
}

/// True when no ignore file can re-include a hidden entry below any of the
/// search's roots. Without roots `rg` searches the cwd. A shell glob root is
/// checked from the directory before its first wildcard, which holds every
/// expansion. A context-free classification has no tree to read, as with
/// path operands.
pub(super) fn roots_proven(roots: &[&str], context: ReadContext<'_>) -> bool {
    if context.home_dir.is_none() && context.cwd.is_none() {
        return true;
    }
    let roots = if roots.is_empty() { &["."][..] } else { roots };
    roots.iter().all(|root| {
        let prefix: Vec<&str> = root
            .split('/')
            .take_while(|part| !part.contains(['*', '?', '[', '{']))
            .collect();
        let prefix = match prefix.join("/") {
            prefix if prefix.is_empty() && root.starts_with('/') => "/".to_owned(),
            prefix if prefix.is_empty() => ".".to_owned(),
            prefix => prefix,
        };
        tree::expanded_operand(&prefix, context)
            .is_some_and(|path| no_hidden_whitelist(&path, context))
    })
}

/// True when no ignore file `rg` honors for a search of `root` can
/// re-include a hidden entry. A root that is not a directory has no walk.
fn no_hidden_whitelist(root: &Path, context: ReadContext<'_>) -> bool {
    let Ok(root) = std::fs::canonicalize(root) else {
        return true;
    };
    if !root.is_dir() {
        return true;
    }
    // The memo key's marker keeps this walk apart from the recursive-read
    // walks that share the same per-evaluation memo.
    super::walk_memo::memoized(&root, &[".rg-whitelist"], &[], false, false, || {
        let mut negations = Negations::default();
        let Some((repository, rules)) = outer_sources_safe(&root, context, &mut negations) else {
            return false;
        };
        let Some((pruned, hidden)) = walk(&root, repository, rules, &mut negations) else {
            return false;
        };
        let matches = |patterns: &[String], names: &[String]| {
            patterns.iter().any(|pattern| {
                names.iter().any(|name| {
                    super::glob_matches(
                        pattern.to_ascii_lowercase().as_bytes(),
                        name.to_ascii_lowercase().as_bytes(),
                    )
                })
            })
        };
        !matches(&negations.all, &pruned)
            && !negations
                .risky
                .iter()
                .any(|risk| hidden.iter().any(|path| risk.re_includes(path)))
    })
}

/// Reads the ignore files `rg` honors above `root`: `.ignore` and
/// `.rgignore` in every ancestor, `.gitignore` up to the repository root,
/// the repository's excludes and the global Git excludes file. Returns
/// whether `root` is inside a Git repository, and the plain rules that
/// prune directories below it.
fn outer_sources_safe(
    root: &Path,
    context: ReadContext<'_>,
    negations: &mut Negations,
) -> Option<(bool, Vec<Rule>)> {
    // Each file with the directory its rules are relative to.
    let mut files: Vec<(PathBuf, PathBuf, bool)> = Vec::new();
    let mut repository = None;
    // Ancestors past the limit would go unread.
    if root.ancestors().count() > MAX_DEPTH {
        return None;
    }
    for directory in root.ancestors().take(MAX_DEPTH) {
        if directory != root {
            for name in [".ignore", ".rgignore"] {
                files.push((directory.join(name), directory.to_path_buf(), false));
            }
            if repository.is_none() {
                files.push((directory.join(".gitignore"), directory.to_path_buf(), true));
            }
        }
        if repository.is_none() && std::fs::symlink_metadata(directory.join(".git")).is_ok() {
            repository = Some(directory.to_path_buf());
        }
    }
    let base = repository.clone().unwrap_or_else(|| root.to_path_buf());
    if let Some(repository) = &repository {
        for git in git_directories(&repository.join(".git"))? {
            files.push((git.join("info/exclude"), base.clone(), true));
        }
    }
    if let Some(home) = context.home_dir.map(Path::new) {
        files.push((home.join(".config/git/ignore"), base.clone(), true));
        for config in [home.join(".gitconfig"), home.join(".config/git/config")] {
            if let Some(lines) = ignore_lines(&config)? {
                for file in excludes_files(&lines, home) {
                    files.push((file, base.clone(), true));
                }
            }
        }
    }
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        files.push((PathBuf::from(xdg).join("git/ignore"), base.clone(), true));
    }
    let mut rules = Vec::new();
    for (file, base, git) in files {
        // `rg` honors Git ignore files only inside a repository.
        if !git || repository.is_some() {
            // `rg` before 15 skips slash rules from files above the search
            // root, so only a root-level file's path rules may prune.
            let found = ignore_rules(&file, &base, git, negations)?;
            rules.extend(found.into_iter().filter(|rule| match &rule.target {
                Target::Name(_) => true,
                Target::Path(_) => base == root,
            }));
        }
    }
    Some((repository.is_some(), rules))
}

/// The Git directory a `.git` entry names, and its common directory when
/// that is a linked worktree's.
fn git_directories(git: &Path) -> Option<Vec<PathBuf>> {
    let metadata = std::fs::symlink_metadata(git).ok()?;
    if metadata.is_dir() {
        return Some(vec![git.to_path_buf()]);
    }
    let text = read_bounded(git)?;
    let named = text.lines().next()?.strip_prefix("gitdir:")?.trim();
    let directory = git.parent()?.join(named);
    let mut directories = vec![directory.clone()];
    if let Some(common) = read_bounded(&directory.join("commondir")) {
        directories.push(directory.join(common.trim()));
    }
    Some(directories)
}

/// `core.excludesFile` values in a Git config file, with `~/` expanded.
fn excludes_files(lines: &[String], home: &Path) -> Vec<PathBuf> {
    lines
        .iter()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            key.trim().eq_ignore_ascii_case("excludesfile").then(|| {
                let value = value.trim().trim_matches('"');
                match value.strip_prefix("~/") {
                    Some(rest) => home.join(rest),
                    None => PathBuf::from(value),
                }
            })
        })
        .collect()
}

/// Walks the directories `rg` may enter below `root`, reading each ignore
/// file there. Returns the directory names it pruned by a plain rule and
/// the paths of the hidden entries it saw. A negation is held against the
/// whole path, not the name alone, because a rule anchored to one directory
/// says nothing about a name of its own below another.
fn walk(
    root: &Path,
    repository: bool,
    outer: Vec<Rule>,
    negations: &mut Negations,
) -> Option<(Vec<String>, Vec<PathBuf>)> {
    let mut pruned = Vec::new();
    let mut hidden = Vec::new();
    let mut pending = vec![(root.to_path_buf(), 0usize, outer, repository)];
    let mut entries = 0usize;
    while let Some((directory, depth, mut rules, in_repository)) = pending.pop() {
        if depth > MAX_DEPTH {
            return None;
        }
        // List first: most directories hold none of `.git` or the ignore
        // files, and each failed open is a filesystem round trip. A listed
        // name is matched without case, as a case-insensitive volume opens it.
        // Only directories that may be walked keep their path.
        let mut has_git = false;
        let mut has_ignore = [false; IGNORE_FILES.len()];
        let mut children = Vec::new();
        for entry in std::fs::read_dir(&directory).ok()? {
            entries += 1;
            if entries > MAX_ENTRIES {
                return None;
            }
            let entry = entry.ok()?;
            let file_name = entry.file_name();
            let name = file_name.to_str()?;
            has_git |= name.eq_ignore_ascii_case(".git");
            for (listed, wanted) in has_ignore.iter_mut().zip(IGNORE_FILES) {
                *listed |= name.eq_ignore_ascii_case(wanted);
            }
            if name.starts_with('.') && name != ".git" {
                hidden.push(entry.path());
            }
            let is_dir = entry.file_type().ok()?.is_dir();
            if is_dir && name != ".git" && (!name.starts_with('.') || benign_hidden(name)) {
                children.push((name.to_owned(), entry.path()));
            }
        }
        let nested =
            depth > 0 && has_git && std::fs::symlink_metadata(directory.join(".git")).is_ok();
        if nested {
            // A nested repository's own `.gitignore` replaces the outer ones.
            rules.retain(|rule| !rule.git);
            // `rg` also honors that repository's own `info/exclude`.
            for git in git_directories(&directory.join(".git"))? {
                rules.extend(ignore_rules(
                    &git.join("info/exclude"),
                    &directory,
                    true,
                    negations,
                )?);
            }
        }
        let in_repository = in_repository || nested;
        for (name, listed) in IGNORE_FILES.into_iter().zip(has_ignore) {
            let git = name == ".gitignore";
            // `rg` honors a `.gitignore` only inside a repository.
            if (!git || in_repository) && listed {
                rules.extend(ignore_rules(
                    &directory.join(name),
                    &directory,
                    git,
                    negations,
                )?);
            }
        }
        for (name, path) in children {
            if rules.iter().any(|rule| rule.prunes(&path, &name)) {
                pruned.push(name);
                continue;
            }
            pending.push((path, depth + 1, rules.clone(), in_repository));
        }
    }
    Some((pruned, hidden))
}

/// Records the negations in one ignore file and returns the plain rules
/// that prune directories, relative to `base`. A missing file has no rules;
/// an unreadable or oversized one fails.
fn ignore_rules(
    path: &Path,
    base: &Path,
    git: bool,
    negations: &mut Negations,
) -> Option<Vec<Rule>> {
    let Some(lines) = ignore_lines(path)? else {
        return Some(Vec::new());
    };
    let mut rules = Vec::new();
    for line in &lines {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(pattern) = line.strip_prefix('!') {
            record_negation(pattern, base, negations);
            continue;
        }
        let line = line.strip_suffix('/').unwrap_or(line);
        let line = line.strip_prefix("**/").unwrap_or(line);
        // A slash at the start or in the middle anchors the rule to the
        // ignore file's directory.
        let (relative, anchored) = match line.strip_prefix('/') {
            Some(relative) => (relative, true),
            None => (line, line.contains('/')),
        };
        if !relative.split('/').all(plain_name) {
            continue;
        }
        let target = if anchored {
            Target::Path(base.join(relative))
        } else {
            Target::Name(relative.to_owned())
        };
        rules.push(Rule { target, git });
    }
    Some(rules)
}

/// Records a negated pattern, with the directory its ignore file applies to
/// and whether each component could name a hidden secret. An escape or empty
/// component matches anything.
fn record_negation(pattern: &str, base: &Path, negations: &mut Negations) {
    let pattern = pattern.strip_suffix('/').unwrap_or(pattern);
    // Git anchors a pattern to its ignore file's directory as soon as it
    // carries a slash anywhere but the end, so only a bare name re-includes
    // entries deeper down. `**` is the exception: it stands for any run of
    // directories, so `!**/.env` and `!src/**/.env` re-include that name
    // however deep it sits, and the anchored reading would miss it.
    let anchored = (pattern.starts_with('/') || pattern.contains('/'))
        && !pattern.split('/').any(|component| component.contains("**"));
    let pattern = pattern.strip_prefix('/').unwrap_or(pattern);
    let mut components = Vec::new();
    let spelled: Vec<&str> = pattern.split('/').collect();
    for (index, component) in spelled.iter().copied().enumerate() {
        if component.is_empty() || component.contains('\\') {
            negations.all.push("*".to_owned());
            components.push(("*".to_owned(), true));
            continue;
        }
        // A `**` that a name follows stands for the run of directories above
        // that name, which is pushed here in its own turn, and names no entry
        // itself. Pushed as a pattern it would match every pruned directory,
        // so `dist/` beside `!**/notes.md` would read as a re-included
        // `dist`. A trailing `**` is the opposite: `!**` re-includes every
        // entry there is, pruned directories among them, so it keeps the
        // pattern that matches them.
        if component != "**" || index + 1 == spelled.len() {
            negations.all.push(component.to_owned());
        }
        let screened = !super::sensitive_path_argument(component)
            && !super::glob_can_select_sensitive_path(component);
        // A wildcard such as `.c[a]rgo` can re-include a whole hidden
        // directory, so it counts whenever it matches a hidden name.
        let harmless = plain_name(component)
            && (!component.starts_with('.') || (screened && benign_hidden(component)));
        components.push((component.to_owned(), !harmless));
    }
    // A `**` pattern is held by its last component at any depth, which
    // re-includes at least what Git does: `!src/**/.env` holds every `.env`
    // below the ignore file rather than only the ones below `src`.
    if !anchored && components.len() > 1 {
        let last = components.pop().expect("components is not empty");
        components = vec![last];
    }
    negations.risky.push(Risk {
        base: base.to_path_buf(),
        components,
        anywhere: !anchored,
    });
}

fn benign_hidden(name: &str) -> bool {
    tree::descendant_allowed(Path::new(name), Path::new(""), false)
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

/// `None` when the file exists but cannot be read within the budget,
/// `Some(None)` when it does not exist.
fn ignore_lines(path: &Path) -> Option<Option<Vec<String>>> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(None),
        Err(_) => None,
        Ok(_) => read_bounded(path).map(|text| Some(text.lines().map(str::to_owned).collect())),
    }
}

fn read_bounded(path: &Path) -> Option<String> {
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_IGNORE_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    (text.len() as u64 <= MAX_IGNORE_BYTES).then_some(text)
}
