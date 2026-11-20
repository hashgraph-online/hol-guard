//! The git half of the user's git rules: git's own options, then the
//! subcommand's. A commit or push that skips its hooks breaks the hook rule;
//! an add, commit or `rm --cached` of the whole tree breaks the staging rule.

use std::path::{Path, PathBuf};

use crate::git_rules_match::Breaks;
use crate::git_rules_state::{Dir, Hooks, State};

/// Git's own options before the subcommand, and the subcommand's rules.
pub(crate) fn git(args: &[&str], hooks: Hooks, state: &State, found: &mut Breaks) {
    let mut settings = Vec::new();
    // A hooks folder chosen through an environment variable is unknown, so
    // it counts as running no hook.
    let mut config_disarms = false;
    let mut dir = state.dir;
    // The folder git works in, while Guard can still name it.
    let mut folder = state.origin.map(Path::to_path_buf);
    let mut redirected = false;
    let mut index = 0;
    while let Some(word) = args.get(index) {
        let next = args.get(index + 1).copied();
        match *word {
            "-C" => {
                if let Some(target) = next {
                    redirected = true;
                    dir = enter(dir, target, state.top);
                    folder = folder
                        .filter(|_| !target.starts_with(['$', '~', '`']))
                        .map(|folder| folder.join(target));
                }
                index += 2;
            }
            "-c" => {
                settings.extend(next.and_then(|pair| pair.split_once('=')));
                index += 2;
            }
            "--config-env" => {
                config_disarms |= next.is_some_and(names_hooks_path);
                index += 2;
            }
            option if option.starts_with("--config-env=") => {
                config_disarms |= names_hooks_path(&option["--config-env=".len()..]);
                index += 1;
            }
            "--git-dir" | "--work-tree" | "--namespace" | "--exec-path" => index += 2,
            option if option.starts_with('-') => index += 1,
            _ => break,
        }
    }
    // A relative hooks folder is read from the top of the tree git works in.
    let selected: Option<PathBuf> = if !redirected {
        state
            .top
            .filter(|_| state.dir != Dir::Elsewhere)
            .map(Path::to_path_buf)
    } else {
        folder
            .as_deref()
            .and_then(crate::git_rules_match::work_tree_top)
            .map(Path::to_path_buf)
    };
    config_disarms |= settings
        .iter()
        .any(|(key, value)| runs_no_hook(key, value, selected.as_deref()));
    let Some(subcommand) = args.get(index) else {
        return;
    };
    let rest = &args[index + 1..];
    let moved = dir != Dir::Root;
    // A commit preview runs no hook and stages nothing. The option is read
    // after the values of the options before it, so a message `--dry-run`
    // is still a message.
    if *subcommand == "commit"
        && split_options(rest, COMMIT_VALUED_LONG)
            .0
            .contains(&"--dry-run")
    {
        return;
    }
    if HOOK_RUNNING.contains(subcommand) && (hooks.off() || config_disarms) {
        found.hook_bypass = true;
    }
    match *subcommand {
        "commit" => commit(rest, moved, found),
        // `git-stage(1)` is Git's own second name for `git-add(1)`: the same
        // builtin, the same options, the same whole-tree staging. Reading the
        // word literally let `git stage -A` past a user rule that stopped
        // `git add -A`.
        "add" | "stage" => add(rest, moved, found),
        "rm" => {
            let (flags, paths) = split_options(rest, &[]);
            let preview = flags.iter().any(|flag| {
                *flag == "--dry-run" || (!flag.starts_with("--") && flag[1..].contains('n'))
            });
            if flags.contains(&"--cached")
                && !preview
                && paths.iter().any(|path| whole_tree(path, moved))
            {
                found.stage_all = true;
            }
        }
        "config" => found.hook_bypass |= config_disarms_hooks(rest),
        "push" | "merge" | "am" | "rebase" | "cherry-pick" | "revert" | "pull" => {
            if rest
                .iter()
                .take_while(|word| **word != "--")
                .any(|word| *word == "--no-verify")
            {
                found.hook_bypass = true;
            }
        }
        _ => {}
    }
}

/// Subcommands that run a hook the user relies on.
const HOOK_RUNNING: &[&str] = &[
    "commit",
    "push",
    "merge",
    "am",
    "rebase",
    "cherry-pick",
    "revert",
    "pull",
];

/// `git commit`: `-n` or `--no-verify` skips the hooks; `-a`, `--all` or a
/// whole-tree pathspec commits every change instead of the staged names.
fn commit(rest: &[&str], moved: bool, found: &mut Breaks) {
    const VALUED_SHORT: &[char] = &['m', 'F', 'c', 'C', 't'];
    let (flags, paths) = split_options(rest, COMMIT_VALUED_LONG);
    for flag in &flags {
        match *flag {
            "--no-verify" => found.hook_bypass = true,
            "--all" => found.stage_all = true,
            long if long.starts_with("--") => {}
            short => {
                for letter in short.trim_start_matches('-').chars() {
                    match letter {
                        'n' => found.hook_bypass = true,
                        'a' => found.stage_all = true,
                        _ => {}
                    }
                    if VALUED_SHORT.contains(&letter) || letter == 'u' || letter == 'S' {
                        break;
                    }
                }
            }
        }
    }
    if paths.iter().any(|path| whole_tree(path, moved)) {
        found.stage_all = true;
    }
}

/// `git commit`'s long options that take a separate value.
const COMMIT_VALUED_LONG: &[&str] = &[
    "--message",
    "--file",
    "--reuse-message",
    "--reedit-message",
    "--fixup",
    "--squash",
    "--author",
    "--date",
    "--template",
    "--cleanup",
    "--trailer",
    "--pathspec-from-file",
];

/// `git add`: everything, every tracked change, or every file but a few.
fn add(rest: &[&str], moved: bool, found: &mut Breaks) {
    let (flags, paths) = split_options(rest, &["--chmod", "--pathspec-from-file"]);
    let mut all = false;
    for flag in &flags {
        match *flag {
            "--all" | "--update" | "--no-ignore-removal" => all = true,
            "--patch" | "--interactive" | "--edit" | "--dry-run" => return,
            long if long.starts_with("--") => {}
            short => {
                for letter in short.trim_start_matches('-').chars() {
                    match letter {
                        'A' | 'u' => all = true,
                        'p' | 'i' | 'e' | 'n' => return,
                        _ => {}
                    }
                }
            }
        }
    }
    let named: Vec<&&str> = paths.iter().filter(|path| !excludes(path)).collect();
    let only_exclusions = named.is_empty() && !paths.is_empty();
    if (named.is_empty() && all)
        || only_exclusions
        || named.iter().any(|path| whole_tree(path, moved))
    {
        found.stage_all = true;
    }
}

/// Splits a subcommand's words into options and pathspecs. Short options
/// that take a value (`-m msg`) are read by the caller from their cluster;
/// their separate value is skipped here.
fn split_options<'a>(rest: &[&'a str], valued_long: &[&str]) -> (Vec<&'a str>, Vec<&'a str>) {
    const VALUED_SHORT: &[char] = &['m', 'F', 'c', 'C', 't'];
    let mut flags = Vec::new();
    let mut paths = Vec::new();
    let mut index = 0;
    while let Some(word) = rest.get(index) {
        index += 1;
        if *word == "--" {
            paths.extend(rest[index..].iter().copied());
            break;
        }
        if let Some(long) = word.strip_prefix("--") {
            flags.push(*word);
            if !long.contains('=') && valued_long.contains(word) {
                index += 1;
            }
        } else if word.len() > 1 && word.starts_with('-') {
            flags.push(*word);
            // The value of the cluster's first valued letter is the rest of
            // the word, or the next word when nothing follows the letter.
            let letters: Vec<char> = word[1..].chars().collect();
            if let Some(at) = letters
                .iter()
                .position(|letter| VALUED_SHORT.contains(letter))
            {
                if at + 1 == letters.len() {
                    index += 1;
                }
            }
        } else {
            paths.push(*word);
        }
    }
    (flags, paths)
}

/// A pathspec that names the whole working tree.
fn whole_tree(path: &str, moved: bool) -> bool {
    if path.contains("--show-toplevel") {
        return true;
    }
    if let Some(rest) = path.strip_prefix(":/") {
        return matches!(rest, "" | "." | "*" | "**");
    }
    if let Some(magic) = path.strip_prefix(":(") {
        if let Some((words, rest)) = magic.split_once(')') {
            return words.split(',').any(|word| word == "top")
                && matches!(rest, "" | "." | "*" | "**");
        }
    }
    !moved && matches!(path, "." | "./" | "*" | "./*" | "**" | "./**")
}

fn excludes(path: &str) -> bool {
    path.starts_with(":!")
        || path.starts_with(":^")
        || path
            .strip_prefix(":(")
            .and_then(|magic| magic.split_once(')'))
            .is_some_and(|(words, _)| words.split(',').any(|word| word == "exclude"))
}

/// The folder after `git -C target`. The top of the tree, an absolute path
/// inside it and a variable that may name it count as the top.
pub(crate) fn enter(dir: Dir, target: &str, top: Option<&Path>) -> Dir {
    if matches!(target, "." | "./") {
        return dir;
    }
    if target.contains("--show-toplevel") || target.starts_with('$') {
        return Dir::Root;
    }
    if target.starts_with('/') {
        return top.map_or(Dir::Root, |top| {
            crate::git_rules_match::below(Path::new(target), top)
        });
    }
    dir.enter(target)
}

/// Whether `--config-env` names `core.hooksPath`.
fn names_hooks_path(pair: &str) -> bool {
    pair.split_once('=')
        .is_some_and(|(key, _)| key.eq_ignore_ascii_case("core.hooksPath"))
}

/// `git config [options] [set] core.hooksPath <value>`: the options that
/// take a value are skipped with it, and a read or an unset never matches.
fn config_disarms_hooks(rest: &[&str]) -> bool {
    const VALUED: &[&str] = &[
        "-f",
        "--file",
        "--blob",
        "--type",
        "--default",
        "--comment",
        "--value",
    ];
    const NOT_A_WRITE: &[&str] = &[
        "--get",
        "--get-all",
        "--get-regexp",
        "--get-urlmatch",
        "--unset",
        "--unset-all",
        "-l",
        "--list",
        "-e",
        "--edit",
        "--remove-section",
        "--rename-section",
        "get",
        "list",
        "unset",
        "edit",
        "remove-section",
        "rename-section",
    ];
    let mut words = Vec::new();
    let mut index = 0;
    while let Some(word) = rest.get(index) {
        index += 1;
        if NOT_A_WRITE.contains(word) {
            return false;
        }
        if VALUED.contains(word) {
            index += 1;
        } else if !word.starts_with('-') {
            words.push(*word);
        }
    }
    if words.first() == Some(&"set") {
        words.remove(0);
    }
    // A saved hooks folder inside the tree is how hook managers install
    // themselves, so only a folder outside it is read.
    matches!(words.as_slice(), [key, value, ..] if runs_no_hook(key, value, None))
}

/// Whether `core.hooksPath = value` points git at a place that runs no
/// hook: nothing, a missing path, a file, or a folder with no hook in it.
/// A relative value is read from `top` and is left alone without it.
fn runs_no_hook(key: &str, value: &str, top: Option<&Path>) -> bool {
    if !key.eq_ignore_ascii_case("core.hooksPath") {
        return false;
    }
    let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
    if matches!(value, "" | "/dev/null" | "NUL" | "nul") {
        return true;
    }
    if value.starts_with(['~', '$', '`']) {
        return false;
    }
    let path = Path::new(value);
    let folder = match (path.is_absolute(), top) {
        (true, _) => path.to_path_buf(),
        (false, Some(top)) => top.join(path),
        (false, None) => return false,
    };
    match std::fs::metadata(&folder) {
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        Ok(metadata) if !metadata.is_dir() => true,
        Ok(_) => std::fs::read_dir(&folder).is_ok_and(|entries| {
            !entries.flatten().take(256).any(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| HOOK_NAMES.contains(&name))
                    && runnable(&entry.path())
            })
        }),
    }
}

/// Whether git can run the hook at `path`: on Unix a file it may execute.
fn runnable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

/// The hooks git runs around a commit, push, merge or rewrite.
const HOOK_NAMES: &[&str] = &[
    "pre-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "pre-merge-commit",
    "pre-push",
    "pre-rebase",
    "post-rewrite",
    "post-merge",
    "post-checkout",
    "applypatch-msg",
    "pre-applypatch",
    "post-applypatch",
    "reference-transaction",
];
