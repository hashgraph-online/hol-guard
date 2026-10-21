//! Search roots and paths that name another repository below home.
//!
//! Agents in one repository spell a sibling as an absolute, `~` or `../`
//! path. A `.git` directory and its ignored build output would make the
//! ordinary metadata walk refuse almost every such root, so this walk follows
//! what `rg` itself searches by default instead: it skips hidden entries and
//! directories the repository's root `.gitignore` names plainly, and screens
//! every other descendant like a recursive read.
//!
//! The model holds only while ignore rules cannot widen the search. An ignore
//! file can whitelist a hidden file such as `.env`, and `rg` searches inside a
//! directory named on its command line even when that directory is ignored.
//! So every component between the repository root and the named directory
//! must be visible, or a hidden project-metadata directory such as `.github`,
//! and not plainly ignored, and any `.ignore` or `.rgignore` file sends the
//! search to review. A negated pattern in a `.gitignore` or the repository's
//! `info/exclude` is kept with the scope git gives it, whether it spells a
//! literal path such as `!.gitkeep` or a glob such as `!src/icons/**/*.js`;
//! hidden entries it re-includes are then screened like any other
//! descendant, where the walk meets them. A negation that can name an entry
//! this walk prunes keeps the search at review, because `rg` would read a
//! subtree the walk never screened. A rule at the repository root therefore
//! holds only the searches that can reach the file it names.
mod negations;

use super::{tree, ReadContext};
use negations::Whitelist;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The same `rg` call is screened by this walk and by the negation walk in
/// `rg_whitelist`, which bounds itself at the same number. A lower bound here
/// decides every search named at a whole sibling repository, and an ordinary
/// one already exceeds ten thousand: this repository counts 11,217 entries
/// below its own root. Refusing to finish looking is not a safety margin —
/// the search goes to review with nothing proven either way.
const MAX_ENTRIES: usize = 100_000;
const MAX_DEPTH: usize = 64;
const MAX_IGNORE_BYTES: u64 = 64 * 1024;
const WHITELISTING_FILES: [&str; 2] = [".ignore", ".rgignore"];
/// `fd` reads `.ignore` like `rg` does, `.fdignore` in place of `.rgignore`,
/// and a global ignore file of its own.
const FD_WHITELISTING_FILES: [&str; 3] = [".ignore", ".rgignore", ".fdignore"];
const FD_GLOBAL_IGNORE: &str = ".config/fd/ignore";

/// True when `value` names a directory of a git working tree strictly below
/// home and every file `rg` would search there clears the descendant screen.
pub(in crate::pretool) fn rg_sibling_repository_root(
    value: &str,
    context: ReadContext<'_>,
) -> bool {
    sibling_repository_root(value, context, &WHITELISTING_FILES)
}

/// [`rg_sibling_repository_root`] for `fd`, which reads its own ignore files.
/// A negation in a `.fdignore` re-includes an entry the walk pruned, and the
/// global ignore file can do the same for every search, so both send the
/// listing to review.
pub(in crate::pretool) fn fd_sibling_repository_root(
    value: &str,
    context: ReadContext<'_>,
) -> bool {
    context.home_dir.is_some_and(|home| {
        std::fs::symlink_metadata(Path::new(home).join(FD_GLOBAL_IGNORE)).is_err()
    }) && sibling_repository_root(value, context, &FD_WHITELISTING_FILES)
}

fn sibling_repository_root(value: &str, context: ReadContext<'_>, whitelisting: &[&str]) -> bool {
    if value.is_empty()
        || value.len() > 4096
        || value.contains(tree::HAZARDS)
        || value.contains(['*', '?', '{', '}'])
        || !literal_brackets(value, context)
        || (value.starts_with('~') && value != "~" && !value.starts_with("~/"))
        || !super::super::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return false;
    }
    let Some(operand) =
        tree::expanded_operand(value, context).and_then(|path| std::fs::canonicalize(path).ok())
    else {
        return false;
    };
    let Some(root) = operand
        .ancestors()
        .find(|path| std::fs::symlink_metadata(path.join(".git")).is_ok())
    else {
        return false;
    };
    operand.is_dir()
        && super::super::git_routes::repository_below_home(root, context)
        && no_whitelisting_ancestor(&operand, context, whitelisting)
        && match ignored_names(root) {
            Some(mut ignored) => {
                reachable_by_default(root, &operand, &mut ignored)
                    && walk(root, &operand, &mut ignored, whitelisting)
            }
            None => false,
        }
}

/// `rg` searches a named directory even when it is ignored or hidden, and
/// would then apply no rule this walk prunes by. Each component from the
/// repository root down to `operand` must be one `rg` reaches on its own, and
/// each intermediate `.gitignore` may negate only an admitted literal path.
fn reachable_by_default(root: &Path, operand: &Path, ignored: &mut Ignored) -> bool {
    let Ok(relative) = operand.strip_prefix(root) else {
        return false;
    };
    let mut directory = root.to_path_buf();
    for (index, component) in relative.components().enumerate() {
        let std::path::Component::Normal(name) = component else {
            return false;
        };
        let Some(name) = name.to_str() else {
            return false;
        };
        // `rg` skips a hidden directory on its own, but searches one named on
        // its command line. Only a project-metadata name the recursive walk
        // also admits, such as `.github`, may be named; `.git` never is.
        let refused_hidden =
            name.starts_with('.') && !tree::descendant_allowed(&directory.join(name), root, false);
        if refused_hidden || ignored.prunes(name, index == 0) {
            return false;
        }
        directory.push(name);
        if directory != operand && !ignored.admit_ignore_file(&directory) {
            return false;
        }
    }
    true
}

/// A sibling repository holds framework routes too, and an agent spells one
/// as `~/badges/app/[slug]`. A word with no bracket is the ordinary case; one
/// with a bracket qualifies only where it carries the same proof a search of
/// the working tree's own route carries: the class matches nothing, so the
/// shell hands the program the path as it was typed, and the tree that path
/// names holds nothing these screens refuse to read.
fn literal_brackets(value: &str, context: ReadContext<'_>) -> bool {
    !value.contains(['[', ']']) || tree::safe_literal_bracket_search_target(value, context)
}

/// `rg` also reads `.ignore` and `.rgignore` files in parent directories.
fn no_whitelisting_ancestor(
    operand: &Path,
    context: ReadContext<'_>,
    whitelisting: &[&str],
) -> bool {
    let Some(home) = context
        .home_dir
        .and_then(|home| std::fs::canonicalize(home).ok())
    else {
        return false;
    };
    operand
        .ancestors()
        .skip(1)
        .take_while(|path| path.starts_with(&home))
        .all(|path| {
            whitelisting
                .iter()
                .all(|name| std::fs::symlink_metadata(path.join(name)).is_err())
        })
}

/// Names the root `.gitignore` ignores at any depth, and names it ignores
/// only directly below the root. Only plain names are used to prune; every
/// other pattern just leaves its matches to the descendant screen.
struct Ignored {
    anywhere: Vec<String>,
    at_root: Vec<String>,
    /// The paths negated patterns re-include. `rg` searches such an entry
    /// even when it is hidden, so the walk screens the hidden entries they
    /// name.
    whitelisted: Vec<Whitelist>,
}

impl Ignored {
    fn prunes(&self, name: &str, directly_below_root: bool) -> bool {
        self.anywhere.iter().any(|ignored| ignored == name)
            || (directly_below_root && self.at_root.iter().any(|ignored| ignored == name))
    }

    /// Whether a negation re-includes `path`, which the walk reached below
    /// the directory its ignore file applies to.
    fn whitelists(&self, path: &Path) -> bool {
        negations::whitelists(&self.whitelisted, path)
    }

    /// Reads the `.gitignore` in `directory`, if any, and admits its
    /// negated patterns. They apply to that directory's tree, not to the
    /// repository's.
    fn admit_ignore_file(&mut self, directory: &Path) -> bool {
        match optional_ignore_lines(&directory.join(".gitignore")) {
            Some(Some(lines)) => self.admit_negations(&lines, directory),
            Some(None) => true,
            None => false,
        }
    }

    /// Records the negated patterns among `lines`, read from an ignore file
    /// that applies to the tree being walked. Whether the name a negation
    /// re-includes is one the descendant screen refuses is decided where the
    /// walk meets the file, so a root rule naming a template beside the
    /// searched directory does not answer for a search that never reaches it.
    fn admit_negations(&mut self, lines: &[String], base: &Path) -> bool {
        negations::admit(
            &mut self.whitelisted,
            lines,
            base,
            &self.anywhere,
            &self.at_root,
        )
    }
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

fn ignored_names(root: &Path) -> Option<Ignored> {
    let mut ignored = Ignored {
        anywhere: Vec::new(),
        at_root: Vec::new(),
        whitelisted: Vec::new(),
    };
    let mut excludes = Vec::new();
    for git_dir in git_directories(root)? {
        excludes.extend(optional_ignore_lines(&git_dir.join("info/exclude"))?.unwrap_or_default());
    }
    let lines = optional_ignore_lines(&root.join(".gitignore"))?.unwrap_or_default();
    for line in &lines {
        let pattern = line.strip_suffix('/').unwrap_or(line);
        let (anchored, name) = match pattern.strip_prefix('/') {
            Some(name) => (true, name),
            None => (false, pattern),
        };
        if !plain_name(name) {
            continue;
        }
        if anchored {
            ignored.at_root.push(name.to_owned());
        } else {
            ignored.anywhere.push(name.to_owned());
        }
    }
    (ignored.admit_negations(&excludes, root) && ignored.admit_negations(&lines, root))
        .then_some(ignored)
}

/// The git directories whose `info/exclude` `rg` may read: `.git` itself, or
/// for a linked worktree its registry entry and the owning repository's.
fn git_directories(root: &Path) -> Option<Vec<PathBuf>> {
    let dot_git = root.join(".git");
    let metadata = std::fs::symlink_metadata(&dot_git).ok()?;
    if metadata.is_dir() {
        return Some(vec![dot_git]);
    }
    let lines = ignore_lines(&dot_git)?;
    let entry = PathBuf::from(lines.first()?.strip_prefix("gitdir: ")?);
    let entry = if entry.is_absolute() {
        entry
    } else {
        root.join(entry)
    };
    let common = entry.parent()?.parent()?.to_path_buf();
    Some(vec![entry, common])
}

/// `Some(None)` when the file is absent, `None` when it cannot be trusted.
fn optional_ignore_lines(path: &Path) -> Option<Option<Vec<String>>> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(None),
        Ok(metadata) if metadata.is_file() => ignore_lines(path).map(Some),
        _ => None,
    }
}

/// Pattern lines of a bounded regular ignore file, or `None` when the file
/// cannot be read.
fn ignore_lines(path: &Path) -> Option<Vec<String>> {
    let file = std::fs::File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(MAX_IGNORE_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    if text.len() as u64 > MAX_IGNORE_BYTES {
        return None;
    }
    let mut lines = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        lines.push(line.to_owned());
    }
    Some(lines)
}

fn walk(root: &Path, operand: &Path, ignored: &mut Ignored, whitelisting: &[&str]) -> bool {
    let mut pending: Vec<(PathBuf, usize)> = vec![(operand.to_path_buf(), 0)];
    let mut inspected = 0_usize;
    while let Some((directory, depth)) = pending.pop() {
        if depth > MAX_DEPTH {
            return false;
        }
        // The directory's own `.gitignore` applies to its entries, so its
        // negations are admitted before any entry is screened.
        if directory != root && !ignored.admit_ignore_file(&directory) {
            return false;
        }
        let Ok(entries) = std::fs::read_dir(&directory) else {
            return false;
        };
        for entry in entries {
            let Ok(entry) = entry else { return false };
            inspected += 1;
            if inspected > MAX_ENTRIES {
                return false;
            }
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                return false;
            };
            if whitelisting.contains(&name) {
                return false;
            }
            // `rg` skips hidden entries unless a negated pattern re-includes
            // them; ignore files themselves were read above.
            if name == ".gitignore" || (name.starts_with('.') && !ignored.whitelists(&path)) {
                continue;
            }
            if ignored.prunes(name, directory == root) {
                continue;
            }
            // The listing already carries each entry's kind on the platforms
            // this runs on, so this reads it instead of spending a `lstat`
            // per entry; it falls back to one only where the filesystem
            // leaves the kind unknown. It answers about the link itself, as
            // `symlink_metadata` does, so a symlink is still neither a
            // directory nor a file and still refuses the proof below.
            let Ok(kind) = entry.file_type() else {
                return false;
            };
            if !tree::descendant_allowed(&path, root, kind.is_file()) {
                return false;
            }
            if kind.is_dir() {
                pending.push((path, depth + 1));
            } else if !kind.is_file() {
                return false;
            }
        }
    }
    true
}

/// True when `value` names one file inside a git working tree below home, or
/// a path that does not exist inside one.
///
/// `rg` searches a file named on its command line whatever the ignore rules
/// say, and `grep` reads no ignore file at all, so the walk the directory
/// rule performs has nothing to decide here:
/// the command opens that one file and no other. What is left is the screen
/// every descendant of a sibling root already passes — no hidden component on
/// the way down, and a name that is not a credential's. A path that does not
/// exist reads nothing at all: it prints an error, as a probe `ls` of the
/// same path does, and agents spell one whenever they guess at a file name.
/// It is admitted under the same component screen, so anything that turns up
/// there before the command runs is a file this rule would have read anyway.
///
/// A parent step is read the same way. `cat ../service-api/package.json` from
/// the checkout beside it names the file the absolute spelling already names,
/// and nothing here is decided on the spelling: the existing part of the path
/// is resolved by the kernel, which is what the command itself would cross,
/// and every screen below reads that resolved location. A relative step that
/// climbs out of the sibling set lands somewhere with no repository root
/// below home above it, where the rule declines as it does for the same place
/// spelled in full.
pub(in crate::pretool) fn named_path(
    value: &str,
    context: ReadContext<'_>,
    allow_absent: bool,
) -> bool {
    if value.is_empty()
        || value.len() > 4096
        || value.contains(tree::HAZARDS)
        || value.contains(['*', '?', '{', '}'])
        || !literal_brackets(value, context)
        || (value.starts_with('~') && value != "~" && !value.starts_with("~/"))
        || !super::super::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return false;
    }
    let Some(operand) = tree::expanded_operand(value, context) else {
        return false;
    };
    let Some((present, missing)) = nearest_present(&operand) else {
        return false;
    };
    let Some(root) = present
        .ancestors()
        .find(|path| std::fs::symlink_metadata(path.join(".git")).is_ok())
    else {
        return false;
    };
    let Ok(relative) = present.strip_prefix(root) else {
        return false;
    };
    if !super::super::git_routes::repository_below_home(root, context) {
        return false;
    }
    let mut named = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return false;
        };
        named.push(name);
        if !tree::descendant_allowed(&named, root, false) {
            return false;
        }
    }
    // Everything below the repository root is screened relative to it, so no
    // screen above sees the directories the repository itself sits in, and
    // `credential_named_path` stands aside as soon as the last component is
    // source code: a repository kept inside a store
    // (`~/Code/secrets/service.ts`) would clear both and open everything it
    // holds. Only the path down to the root is read here. The components
    // below it keep the screen they already have, which is the one that
    // knows a test tree's fixtures from a store and a source file from a
    // credential, so `src/auth.ts` stays the source file it is named after.
    if guard_secure_fs::credential_directory_path(root) {
        return false;
    }
    if missing.is_empty() {
        return present.is_file() && tree::descendant_allowed(&present, root, true);
    }
    // Every missing name is screened as a file, not only the last one. The
    // screen answers for the path as it stands when the command is prepared,
    // and a name that is absent then may be anything by the time `rg` opens
    // it; holding each one to the narrower screen means the thing that turns
    // up there cannot be a store `rg` would then walk.
    allow_absent
        && present.is_dir()
        && missing.iter().all(|name| {
            named.push(name);
            tree::descendant_allowed(&named, root, true)
        })
}

/// The resolved nearest existing ancestor of `path`, and the names missing
/// below it, outermost first. `None` when a component cannot be read at all.
fn nearest_present(path: &Path) -> Option<(PathBuf, Vec<String>)> {
    let mut missing: Vec<String> = Vec::new();
    let mut present = path;
    loop {
        match std::fs::symlink_metadata(present) {
            Ok(_) => {
                missing.reverse();
                // The spelled path may cross a link, so the screen reads the
                // place it lands rather than the name it was given.
                return std::fs::canonicalize(present)
                    .ok()
                    .map(|present| (present, missing));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = present.file_name()?.to_str()?;
                missing.push(name.to_owned());
                present = present.parent()?;
            }
            Err(_) => return None,
        }
    }
}

/// Whether the operand, as it was spelled, crosses only names a walk admits.
///
/// The screens below read the resolved path, so a link's own name never
/// reaches them: `service-api/.private` is screened as whatever it points at,
/// and a hidden name would be laundered through the link. The spelling is
/// held to the same hidden-name screen first, before anything is resolved.
fn spelling_allowed(value: &str) -> bool {
    value
        .trim_start_matches('~')
        .split(['/', '\\'])
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .all(|part| !part.starts_with('.') || tree::hidden_allowed(part))
}

/// True when `value` names a directory inside a git working tree below home
/// that a `grep -r` walk may take as its root.
///
/// `grep -r` reads no ignore file: it visits every descendant, so the walk
/// [`tree::walk`] performs is the whole proof, and it is the same walk a root
/// inside the current directory gets. The only thing a root outside the
/// current directory changes is which tree is read, and a repository below
/// home is one the agent works in. `.git`, `node_modules`, `.env` and every
/// other screened name still stop the walk wherever they appear, so
/// `grep -rn pat ~/code/api` is refused for its own `.git` while
/// `grep -rn pat ~/code/api/tests` is read.
///
/// Each component from the repository root down to the operand is screened
/// too: without that, a root could be named straight through a directory the
/// walk itself would refuse to enter.
pub(in crate::pretool) fn grep_walk_root(
    value: &str,
    context: ReadContext<'_>,
    excluded_files: &[&str],
    excluded_directories: &[&str],
    git_metadata: bool,
) -> bool {
    if value.is_empty()
        || value.len() > 4096
        || value.contains(tree::HAZARDS)
        || value.contains(['*', '?', '{', '}'])
        || !literal_brackets(value, context)
        || (value.starts_with('~') && value != "~" && !value.starts_with("~/"))
        || !super::super::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return false;
    }
    if !spelling_allowed(value) {
        return false;
    }
    let Some(operand) =
        tree::expanded_operand(value, context).and_then(|path| std::fs::canonicalize(path).ok())
    else {
        return false;
    };
    if !operand.is_dir()
        || tree::inside_agent_state(&operand, context)
        // The walk measures its descendants against the operand, so a store
        // named as the root has its own name stripped before any of them is
        // screened: `grep -rn pat ~/Code/org/service-api/secrets` would read
        // the store one file at a time. The directories on the way to the
        // root are screened on their own.
        || guard_secure_fs::credential_directory_path(&operand)
    {
        return false;
    }
    let Some(root) = operand
        .ancestors()
        .find(|path| std::fs::symlink_metadata(path.join(".git")).is_ok())
    else {
        return false;
    };
    let Ok(relative) = operand.strip_prefix(root) else {
        return false;
    };
    if !super::super::git_routes::repository_below_home(root, context) {
        return false;
    }
    let mut named = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return false;
        };
        named.push(name);
        if !tree::descendant_allowed(&named, root, false) {
            return false;
        }
    }
    // The caller reaches this route only where the command follows no
    // link, so the walk does not either.
    tree::walk(
        operand,
        excluded_files,
        excluded_directories,
        git_metadata,
        false,
    )
}
