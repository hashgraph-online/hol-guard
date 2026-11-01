//! Where a Git checkout lands when an extension permission allows it.
//!
//! An enabled Git permission (`worktree`, `clone`) settles the review an
//! ordinary checkout would get, so a sibling worktree or a clone into a
//! project folder runs silently. It must not also settle a checkout that
//! plants a tree where something loads it without asking: a launch agent or
//! autostart folder, harness configuration (`~/.claude/agents`, `~/.codex`),
//! git internals and hooks, CI workflows, or a home `bin` directory. Those
//! destinations stay a floor no permission reaches, exactly as a plain
//! `mkdir` into them is.

use std::path::{Component, Path, PathBuf};

use super::super::PathContext;

#[path = "checkout_destination_options.rs"]
mod options;

/// Git subcommands that create a checkout or repository at a path.
const CHECKOUT_SUBCOMMANDS: &[&str] = &["clone", "init", "submodule", "worktree"];
/// `git worktree` actions that create or relocate a checkout.
const CHECKOUT_WORKTREE_ACTIONS: &[&str] = &["add", "move"];
/// Global options whose separate value is a directory Git uses.
const GLOBAL_PATH_OPTIONS: &[&str] = &["--git-dir", "--work-tree"];
/// Bounds the directories a compound can `cd` through before a checkout.
const MAX_BASES: usize = 16;

/// Whether any Git step in `model` creates or moves a checkout into a
/// protected location. Every path-shaped word of the step is screened
/// against the cwd and each directory the compound enters, both as spelled
/// and as the filesystem resolves it, so a symlink cannot hide a protected
/// target. A word or directory that cannot be located fails closed.
pub(crate) fn protected_checkout_destination(
    model: &crate::CanonicalCommandV1,
    context: PathContext<'_>,
) -> bool {
    if !model.segments.iter().any(checkout_step) {
        return false;
    }
    let screen = Screen::new(context);
    let mut bases: Vec<PathBuf> = context
        .cwd
        .and_then(|cwd| expand_word(cwd, context))
        .into_iter()
        .collect();
    // Set once a step enters a directory the text cannot fix; every later
    // checkout then fails closed.
    let mut unknown = false;
    for segment in &model.segments {
        if checkout_step(segment) {
            if unknown {
                return true;
            }
            let Some((step_bases, words)) = step_words(segment, &bases, context) else {
                return true;
            };
            let protected = words.iter().any(|word| {
                located_candidates(word, &step_bases, context).is_none_or(|paths| {
                    paths
                        .iter()
                        .any(|(path, resolved)| screen.protected(path, *resolved))
                })
            });
            if protected {
                return true;
            }
        }
        match entered_directories(segment, &bases, context) {
            Some(entered) if bases.len() + entered.len() <= MAX_BASES => bases.extend(entered),
            _ => unknown = true,
        }
    }
    false
}

fn git_segment(segment: &crate::CommandSegmentV1) -> bool {
    segment.executable.as_deref().is_some_and(|executable| {
        let name = super::super::executable_basename(executable).to_ascii_lowercase();
        name == "git" || name == "git.exe"
    })
}

fn checkout_step(segment: &crate::CommandSegmentV1) -> bool {
    if !git_segment(segment) {
        return false;
    }
    let arguments = &segment.arguments;
    let Some(index) = crate::command_compatibility::git_command_index(arguments) else {
        // An unknown global option hides the subcommand. When any word could
        // be a checkout subcommand, treat the step as one; step_words then
        // fails closed because it cannot tell options from paths.
        return arguments
            .iter()
            .any(|argument| CHECKOUT_SUBCOMMANDS.contains(&argument.as_str()));
    };
    match arguments.get(index).map(String::as_str) {
        Some("worktree") => arguments
            .get(index + 1)
            .is_some_and(|action| CHECKOUT_WORKTREE_ACTIONS.contains(&action.as_str())),
        Some("submodule") => arguments[index + 1..]
            .iter()
            .any(|argument| argument == "add"),
        Some(subcommand) => CHECKOUT_SUBCOMMANDS.contains(&subcommand),
        None => false,
    }
}

/// The directories a `cd` or `pushd` step can enter, each resolved against
/// every directory known before it; empty for any other step. `None` when
/// the step enters a directory the text cannot fix.
fn entered_directories(
    segment: &crate::CommandSegmentV1,
    bases: &[PathBuf],
    context: PathContext<'_>,
) -> Option<Vec<PathBuf>> {
    let Some(executable) = segment.executable.as_deref() else {
        return Some(Vec::new());
    };
    if !matches!(
        super::super::executable_basename(executable),
        "cd" | "pushd"
    ) {
        return Some(Vec::new());
    }
    let target = segment
        .arguments
        .iter()
        .find(|argument| !matches!(argument.as_str(), "-L" | "-P" | "-e" | "-@" | "--"));
    match target {
        None => Some(vec![PathBuf::from(context.home_dir?)]),
        Some(target) if target == "-" || unresolved_word(target) => None,
        Some(target) => {
            let expanded = expand_word(target, context)?;
            if expanded.is_absolute() {
                return Some(vec![expanded]);
            }
            // POSIX `cd` searches CDPATH for a relative operand unless it
            // starts with `.` or `..`, and nothing joins a relative operand
            // when no directory is known.
            let dotted = matches!(target.as_str(), "." | "..")
                || target.starts_with("./")
                || target.starts_with("../");
            if bases.is_empty() || (!dotted && !context.cdpath_unset) {
                return None;
            }
            Some(bases.iter().map(|base| base.join(&expanded)).collect())
        }
    }
}

/// The directories a Git step resolves relative words against (its `-C`
/// directories applied to `bases`) and the words to screen: the checkout
/// directory itself, every word after the subcommand, the value of every
/// `--option=value`, and the global `--git-dir` and `--work-tree` values.
/// Option names and the repository of a clone or submodule add are not
/// paths and are skipped; the directory Git names after that repository is
/// screened in its place.
/// The cwd and each directory entered before the step are its bases.
fn step_words(
    segment: &crate::CommandSegmentV1,
    bases: &[PathBuf],
    context: PathContext<'_>,
) -> Option<(Vec<PathBuf>, Vec<String>)> {
    let arguments = &segment.arguments;
    let index = crate::command_compatibility::git_command_index(arguments)?;
    let mut step_bases = bases.to_vec();
    let mut words = vec![".".to_owned()];
    let mut position = 0;
    while position < index {
        let argument = &arguments[position];
        let (option, inline) = match argument.split_once('=') {
            Some((option, value)) if option.starts_with("--") => (option, Some(value)),
            _ => (argument.as_str(), None),
        };
        let attached = argument
            .strip_prefix("-C")
            .filter(|value| !value.is_empty() && !argument.starts_with("--"));
        if option == "-C" || attached.is_some() {
            let value = match attached {
                Some(value) => value,
                None => {
                    position += 1;
                    arguments.get(position)?.as_str()
                }
            };
            if unresolved_word(value) {
                return None;
            }
            let entered = expand_word(value, context)?;
            step_bases = if entered.is_absolute() {
                vec![entered]
            } else if step_bases.is_empty() {
                return None;
            } else {
                step_bases.iter().map(|base| base.join(&entered)).collect()
            };
        } else if GLOBAL_PATH_OPTIONS.contains(&option) {
            match inline {
                Some(value) => words.push(value.to_owned()),
                None => {
                    position += 1;
                    words.push(arguments.get(position)?.clone());
                }
            }
        }
        position += 1;
    }
    // After `--` every word is an operand, even one that starts with `-`.
    let mut operands = Vec::new();
    let mut terminated = false;
    let mut value_pending = false;
    for argument in arguments.iter().skip(index + 1) {
        if value_pending {
            // An option's separate value is screened, never an operand.
            value_pending = false;
            words.push(argument.clone());
            continue;
        }
        if !terminated && argument == "--" {
            terminated = true;
            continue;
        }
        if !terminated {
            if let Some(rest) = argument.strip_prefix('-') {
                match rest.split_once('=') {
                    Some((_, value)) => words.push(value.to_owned()),
                    None => value_pending = options::takes_separate_value(argument),
                }
                continue;
            }
        }
        operands.push(argument.clone());
    }
    words.extend(operands.iter().cloned());
    if matches!(arguments[index].as_str(), "clone" | "submodule") {
        // The repository is the first remote-shaped word; no other word is
        // exempt from screening. With no directory after it, Git names the
        // checkout after the repository in the step's directory. Options may
        // follow either operand, so the name Git would guess from every
        // operand is screened.
        // Only an operand can be the repository: an option value shaped like
        // a remote is still a path Git writes to.
        if let Some(position) = operands.iter().position(|word| remote_word(word)) {
            let offset = words.len() - operands.len();
            words.remove(offset + position);
        }
        for operand in &operands {
            words.extend(guessed_directories(operand)?);
        }
    }
    if words.iter().any(|word| unresolved_word(word)) {
        return None;
    }
    Some((step_bases, words))
}

/// A URL or an SCP-style `host:path` remote, which Git never opens as a
/// local directory. A word with a `..` component is always screened as a
/// path: as a destination, `ab:/../../x` is a directory that climbs out.
fn remote_word(word: &str) -> bool {
    if word.split(['/', '\\']).any(|part| part == "..") {
        return false;
    }
    if word.contains("://") {
        return true;
    }
    let Some((host, _)) = word.split_once(':') else {
        return false;
    };
    host.len() > 1 && !host.contains(['/', '\\']) && !host.starts_with(['.', '~'])
}

/// The directory `git clone <repository>` creates when none is given, the
/// way Git guesses it: trailing separators, whitespace and `/.git` dropped,
/// the scheme and any authentication skipped, a bare `host:port` reduced to
/// the host, the last component without `.git`, and runs of whitespace and
/// control characters collapsed to one space and trimmed. Git strips
/// `.bundle` only from a bundle file, so a name ending in it is screened in
/// both forms. `None` when nothing is left to name it.
fn guessed_directories(repository: &str) -> Option<Vec<String>> {
    let separator = |c: char| c == '/' || c == '\\';
    let mut trimmed =
        repository.trim_end_matches(|c: char| separator(c) || c.is_ascii_whitespace());
    if let Some(parent) = trimmed
        .strip_suffix(".git")
        .and_then(|rest| rest.strip_suffix(separator))
        .filter(|parent| !parent.is_empty())
    {
        trimmed = parent.trim_end_matches(separator);
    }
    // Git reads the name past the scheme and past authentication, and only
    // then asks whether what is left is a bare host and port. Reading those
    // over the whole word names `https://hooks:443` after its port and
    // `ssh://git@LaunchAgents` after its user, so the directory Git would
    // create goes unscreened.
    trimmed = &trimmed[trimmed.find("://").map_or(0, |at| at + 3)..];
    // Authentication is stripped greedily, up to the last `@` before the
    // first separator.
    let mut authentication = None;
    for (at, character) in trimmed.char_indices() {
        if separator(character) {
            break;
        }
        if character == '@' {
            authentication = Some(at + character.len_utf8());
        }
    }
    if let Some(at) = authentication {
        trimmed = &trimmed[at..];
    }
    if !trimmed.contains('/') {
        if let Some((host, port)) = trimmed.rsplit_once(':') {
            if port.bytes().all(|byte| byte.is_ascii_digit()) {
                trimmed = host;
            }
        }
    }
    let name = trimmed.rsplit(|c: char| separator(c) || c == ':').next()?;
    let mut names = vec![name.strip_suffix(".git").unwrap_or(name)];
    names.extend(name.strip_suffix(".bundle"));
    let names: Vec<String> = names
        .into_iter()
        .map(|name| {
            name.split(|c: char| c.is_ascii_whitespace() || c.is_ascii_control())
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    (!names.iter().any(String::is_empty)).then_some(names)
}

/// A word the shell rewrites before Git sees it: an expansion, a command
/// substitution, a glob or a brace list.
fn unresolved_word(word: &str) -> bool {
    word.contains(['$', '`', '*', '?', '[', '{'])
}

fn expand_word(word: &str, context: PathContext<'_>) -> Option<PathBuf> {
    if word.starts_with('~') {
        return super::super::read_paths::expand_home_read_path(word, context.home_dir)
            .map(PathBuf::from);
    }
    Some(PathBuf::from(word))
}

/// Each place `word` can name: as spelled with `..` folded, and where the
/// filesystem takes it, walking `..` physically as Git does (flagged
/// `true`). `None` when it cannot be located.
fn located_candidates(
    word: &str,
    bases: &[PathBuf],
    context: PathContext<'_>,
) -> Option<Vec<(PathBuf, bool)>> {
    let expanded = expand_word(word, context)?;
    let targets: Vec<PathBuf> = if expanded.is_absolute() {
        vec![expanded]
    } else if bases.is_empty() {
        // No cwd to resolve against, so a link there cannot be followed.
        return None;
    } else {
        bases.iter().map(|base| base.join(&expanded)).collect()
    };
    let mut located = Vec::with_capacity(targets.len() * 2);
    for target in targets {
        located.push((resolved_path(&target)?, true));
        located.push((lexical_path(&target), false));
    }
    Some(located)
}

/// The canonical path of an existing entry, or of a new one below its
/// nearest existing ancestor. A dangling link or a file on the way fails.
fn resolved_path(target: &Path) -> Option<PathBuf> {
    match std::fs::symlink_metadata(target) {
        Ok(_) => std::fs::canonicalize(target).ok(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            super::super::worktree_writes::canonical_write_target(target)
        }
        Err(_) => None,
    }
}

fn lexical_path(path: &Path) -> PathBuf {
    let mut folded = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                folded.pop();
            }
            other => folded.push(other.as_os_str()),
        }
    }
    folded
}

struct Screen {
    homes: Vec<PathBuf>,
    workspaces: Vec<PathBuf>,
    home_dir: Option<String>,
    workspace: Option<String>,
}

impl Screen {
    fn new(context: PathContext<'_>) -> Self {
        let both = |value: Option<&str>| -> Vec<PathBuf> {
            let Some(value) = value else {
                return Vec::new();
            };
            let spelled = lexical_path(Path::new(value));
            let mut paths = vec![spelled.clone()];
            if let Ok(canonical) = std::fs::canonicalize(&spelled) {
                if canonical != spelled {
                    paths.push(canonical);
                }
            }
            paths
        };
        Self {
            homes: both(context.home_dir),
            workspaces: both(context.cwd),
            home_dir: context.home_dir.map(str::to_owned),
            workspace: context.cwd.map(str::to_owned),
        }
    }

    /// Whether `path` is a protected checkout location. Hooks configuration
    /// is matched against resolved paths only, as its screen expects.
    fn protected(&self, path: &Path, resolved: bool) -> bool {
        let lowered = parts(path);
        let below = self.below_shared_anchor(&lowered);
        // A path never starts with its own child, so passing one turns off
        // the screen's workspace exemption, which is applied here instead.
        let outside = path.join("\0");
        let inside_workspace = self
            .workspaces
            .iter()
            .any(|workspace| path.starts_with(workspace));
        lowered.iter().any(|part| part == ".git")
            || super::screens::autostart_write_target(path)
            // The workspace's own name is not judged as a secret file name.
            || (!below.is_empty() && guard_secure_fs::sensitive_path_family(path).is_some())
            || (!inside_workspace
                && self.homes.iter().any(|home| {
                    path.starts_with(home)
                        && super::screens::home_execution_control_target(path, home, &outside)
                }))
            || (resolved
                && super::hooks_path::configured_hooks_write(
                    path,
                    self.home_dir.as_deref(),
                    self.workspace.as_deref(),
                ))
            || crate::harness_config_names::path_parts_protected(below.iter().map(String::as_str))
            || below
                .iter()
                .any(|part| super::screens::guarded_dot_part(part))
    }

    /// The components of `path` below the deepest directory it shares with
    /// the workspace, so a sibling worktree of a workspace that itself lives
    /// under a hidden folder (`~/.codex/worktrees/<id>/repo`) is judged by
    /// its own name. A shared directory whose name is hidden is no anchor:
    /// `~/.codex/skills` and a workspace under `~/.codex/worktrees` share
    /// only `~/.codex`, so the whole path is judged.
    fn below_shared_anchor<'a>(&self, lowered: &'a [String]) -> &'a [String] {
        let shared = self
            .workspaces
            .iter()
            .map(|workspace| {
                let workspace = parts(workspace);
                let mut depth = lowered
                    .iter()
                    .zip(&workspace)
                    .take_while(|(left, right)| left == right)
                    .count();
                while depth > 0 && lowered[depth - 1].starts_with('.') {
                    depth -= 1;
                }
                depth
            })
            .max()
            .unwrap_or(0);
        &lowered[shared..]
    }
}

fn parts(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
#[path = "checkout_destination_floor_tests.rs"]
mod tests;
