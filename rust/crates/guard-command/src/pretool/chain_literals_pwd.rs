//! `ln -s "$(pwd)/node_modules" ../wt/node_modules` names the working
//! directory through an expansion, so the whole command stayed opaque. Until
//! something in the list can change the directory, `$(pwd)`, `` `pwd` ``,
//! `$PWD` and `${PWD}` all expand to the session's verified working
//! directory. Writing that path in their place lets each step be judged on
//! the path it really names. Anything this pass does not fully understand
//! returns `None`, so the expansion stays opaque.
//!
//! Two substitutions print a path derived from that directory and nothing
//! else. `$(dirname "$PWD")` prints its parent, computed the way `dirname`
//! computes it, from the text alone. `$(git rev-parse --show-toplevel)`
//! prints the root of the worktree holding it, found the way Git finds it:
//! the nearest `.git` above the real directory. A `.git` Git could read
//! differently, through a link, an include, a configured worktree or a
//! layout this pass does not check, keeps the command opaque instead of
//! guessing. Each producer must also be allowed as its own command (for
//! `dirname`, which reads no file, a run the workspace sandbox contains also
//! counts), so lockdown, managed policy and extension controls on it still
//! hold.
//!
//! The arguments of a `cd` expand before it runs, so a `cd` that holds the
//! last use still sees the directory the uses were written against:
//! `cd "$(git rev-parse --show-toplevel)" && git status --short` is judged as
//! that `cd` to the literal root.

use std::path::Path;

use super::lex::{items, names_variable, tokenize};
use super::{assignment, listed, KEYWORDS, MAX_COMMAND_CHARS, PRECOMMANDS, STATE_COMMANDS};

const MAX_DIRECTORY_CHARS: usize = 1024;
/// A `.git` file or configuration larger than this is not read.
const MAX_GIT_FILE_BYTES: u64 = 64 * 1024;
/// Variables that change where Git looks for a repository, what it accepts
/// or how it reads its configuration.
const GIT_DISCOVERY_VARIABLES: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
];

/// Builtins that change the shell's directory or its idea of it.
const DIRECTORY_COMMANDS: &str = "cd chdir dirs popd pushd";

/// Builtins that take the variable they set as an option operand rather than
/// as a bare word: `printf -v` in bash and zsh, and zsh's `print -v`.
/// `names_variable` reads a bare name, so it sees `printf -v HOME`, but not a
/// name the shell assembles from expansions, as
/// `printf -v $prefix$suffix %s /other/home` does. Any `-v` on one of these
/// keeps the chain opaque.
const OPTION_SETTERS: &str = "print printf";

/// Builtins that set a variable named by an operand: bash's `compgen -V`,
/// and zsh's module builtins (`getln`, `sysread`, `strftime -s`, `zstat -A`,
/// `zformat -f`, `pcre_match -v`, `zgetattr` and the rest). The ones that
/// also run text as code are in `STATE_COMMANDS`. The substitution pass
/// stops at any operand it cannot resolve, but this pass
/// reads only command words, so a name the shell assembles from expansions
/// (`p=HO s=ME; syserror -e $p$s`) would reach one unseen. zsh/stat's `stat`
/// is left out: it shadows the external command only once a chain or the
/// user's own startup files load that module, and a chain that does is
/// already opaque through `zmodload`.
const NAME_SETTERS: &str = "compadd compgen getln pcre_match strftime sysopen syserror sysread \
    syswrite zcurses zformat zgetattr zlistattr zpty zselect zstat zsystem ztie";

/// The spellings of the parent directory's substitution.
const PARENT_USES: &[&str] = &[
    "$(dirname \"$PWD\")",
    "$(dirname $PWD)",
    "$(dirname \"${PWD}\")",
    "$(dirname ${PWD})",
];
const TOPLEVEL_USE: &str = "$(git rev-parse --show-toplevel)";
const TOPLEVEL_COMMAND: &str = "git rev-parse --show-toplevel";

/// What a recognized use expands to.
#[derive(Clone, Copy, PartialEq)]
enum Use {
    Directory,
    Parent,
    Toplevel,
}

/// The values each kind of use prints, resolved on first use.
struct Values<'a, F> {
    cwd: &'a str,
    allowed: F,
    parent: Option<Option<String>>,
    toplevel: Option<Option<String>>,
}

impl<F: Fn(&str) -> bool> Values<'_, F> {
    fn value(&mut self, kind: Use) -> Option<String> {
        let cwd = self.cwd;
        match kind {
            Use::Directory => Some(cwd.to_owned()),
            Use::Parent => {
                let allowed = &self.allowed;
                self.parent
                    .get_or_insert_with(|| {
                        allowed(&format!("dirname {cwd}"))
                            .then(|| parent(cwd))
                            .flatten()
                    })
                    .clone()
            }
            Use::Toplevel => {
                let allowed = &self.allowed;
                self.toplevel
                    .get_or_insert_with(|| {
                        allowed(TOPLEVEL_COMMAND)
                            .then(|| repository_root(cwd))
                            .flatten()
                    })
                    .clone()
            }
        }
    }
}

/// A use at the start of the text: its length, the path it prints, and
/// whether it must sit in a plain first step.
type Found = (usize, String, bool);

/// The command with each working-directory expansion replaced by the path it
/// prints; `None` when nothing is replaced, the directory is not a plain
/// absolute literal, a derived path is unknown or its producer is not
/// allowed, or any step before a replaced use could change the directory.
pub(super) fn project(command: &str, cwd: &str, allowed: impl Fn(&str) -> bool) -> Option<String> {
    let mut values = Values {
        cwd,
        allowed,
        parent: None,
        toplevel: None,
    };
    project_found(
        command,
        cwd,
        "PWD",
        |rest| {
            let Some((width, kind)) = use_at(rest)? else {
                return Some(None);
            };
            // The root comes from `.git` as it is now. A step that runs
            // first, such as `git init`, could move it, and so could a
            // pipeline stage running beside it.
            Some(Some((width, values.value(kind)?, kind == Use::Toplevel)))
        },
        |word| {
            listed(DIRECTORY_COMMANDS, word)
                // zsh's AUTO_CD runs a bare directory name as `cd`.
                || Path::new(cwd).join(word).is_dir()
        },
    )
}

/// The command with each use `width` recognizes replaced by `value`, a
/// directory the variable `name` is known to hold; `None` when nothing is
/// replaced, the value is not a plain absolute literal, or any step at or
/// before a replaced use could set the variable or is a word `changes` names.
pub(super) fn project_uses(
    command: &str,
    value: &str,
    name: &str,
    width: fn(&[char]) -> Option<usize>,
    changes: impl Fn(&str) -> bool,
) -> Option<String> {
    project_found(
        command,
        value,
        name,
        |rest| {
            Some(match width(rest)? {
                0 => None,
                width => Some((width, value.to_owned(), false)),
            })
        },
        changes,
    )
}

/// The command with each use `found` recognizes replaced by the path it
/// prints, under the rules of [`project_uses`].
fn project_found(
    command: &str,
    value: &str,
    name: &str,
    found: impl FnMut(&[char]) -> Option<Option<Found>>,
    changes: impl Fn(&str) -> bool,
) -> Option<String> {
    if !literal_directory(value)
        || !command.is_ascii()
        || command.len() > MAX_COMMAND_CHARS
        || command.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        // A changed `IFS` splits an unquoted use where the literal is whole,
        // and any other mention of the variable might set it.
        || names_variable(command, |named| named == "IFS" || named == name)
    {
        return None;
    }
    let chars: Vec<char> = command.chars().collect();
    let (projected, last_use, first_step) = replace_uses(&chars, value.len(), found)?;
    let projected_chars: Vec<char> = projected.chars().collect();
    let tokens = tokenize(&projected_chars)?;
    let list = items(&tokens)?;
    if first_step {
        let stages = &list.first()?.0;
        if stages.len() != 1 || stages[0].last().is_none_or(|&(_, end)| end < last_use) {
            return None;
        }
    }
    // Every replacement ends no later than `last_use` in the projection, so
    // each step that starts before it runs before or alongside a use.
    for (stages, _) in &list {
        let first = stages.first()?.first()?.0;
        if first >= last_use {
            break;
        }
        for stage in stages {
            let leading = stage
                .iter()
                .take_while(|&&(from, to)| assignment(&projected_chars[from..to]).is_some())
                .count();
            // The lexer keeps redirections as words, so one before the
            // command word (`2>/dev/null cd /etc`) would hide that word.
            if stage[..stage.len().min(leading + 1)]
                .iter()
                .any(|&(from, to)| {
                    projected_chars[from..to]
                        .iter()
                        .any(|c| matches!(c, '<' | '>'))
                })
            {
                return None;
            }
            let Some(&(from, to)) = stage.get(leading) else {
                continue;
            };
            let word: String = projected_chars[from..to]
                .iter()
                .filter(|&&c| !matches!(c, '\'' | '"' | '\\'))
                .collect();
            // A lone `cd` that holds the last use expands every use before
            // it changes the directory. In a pipeline it could run beside a
            // stage that reads the directory, so only a plain step counts.
            let holds_last_use = stage.last().is_some_and(|&(_, end)| last_use <= end);
            if word == "cd" && leading == 0 && stages.len() == 1 && holds_last_use {
                continue;
            }
            if word.contains('$')
                || listed(STATE_COMMANDS, &word)
                || listed(KEYWORDS, &word)
                || listed(PRECOMMANDS, &word)
                || listed(NAME_SETTERS, &word)
                || changes(word.as_str())
            {
                return None;
            }
            if listed(OPTION_SETTERS, &word)
                && sets_a_variable(
                    stage[leading + 1..]
                        .iter()
                        .map(|&(from, to)| &projected_chars[from..to]),
                )
            {
                return None;
            }
        }
    }
    Some(projected)
}

/// Whether an [`OPTION_SETTERS`] builtin may read one of its operands as the
/// `-v` option, in the separate (`-v NAME`) or the attached (`-vNAME`) form.
/// The builtin stops reading options at the first operand that is not one, so
/// only the leading run is read. A word the shell still has to expand, brace
/// out or glob, such as the `$o` of `o=-v; printf $o $p$s %s /etc` or the
/// `-$x` of `x=v; printf -$x$p$s %s /etc`, can spell that option, and one
/// starting with `-` can be it outright. The shell removes quotes and escapes
/// before the builtin reads the word, so they are removed here too.
fn sets_a_variable<'a>(operands: impl Iterator<Item = &'a [char]>) -> bool {
    for word in operands {
        let mut chars = word.iter().filter(|&&c| !matches!(c, '\'' | '"' | '\\'));
        // Its text is unknown, so it may be the option wherever one could stand.
        if chars
            .clone()
            .any(|&c| matches!(c, '$' | '`' | '{' | '[' | '*' | '?'))
        {
            return true;
        }
        match chars.next() {
            Some('-') if chars.any(|&c| c == 'v') => return true,
            Some('-') => {}
            _ => return false,
        }
    }
    false
}

/// An absolute path whose characters the shell never splits, globs, quotes
/// or expands, and which still names a directory.
fn literal_directory(cwd: &str) -> bool {
    literal_path(cwd) && std::fs::canonicalize(cwd).is_ok_and(|path| path.is_dir())
}

/// An absolute path whose characters the shell never splits, globs, quotes
/// or expands, with no `..` to climb out of what it names.
fn literal_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= MAX_DIRECTORY_CHARS
        && !path.split('/').any(|part| part == "..")
        && path.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '_' | '.' | '/' | '@' | '%' | '+' | ':' | ',' | '-')
        })
}

/// What `dirname` prints for an absolute path: the text before its last
/// component, without trailing slashes, or `/`. The shell sets `$PWD` to a
/// canonical spelling, so a path with a `.` component or a doubled slash,
/// whose text differs from that spelling, has no known parent.
fn parent(path: &str) -> Option<String> {
    if path.split('/').any(|part| part == ".") || path.contains("//") {
        return None;
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return Some("/".to_owned());
    }
    let (head, _) = trimmed.rsplit_once('/')?;
    let head = head.trim_end_matches('/');
    Some(if head.is_empty() { "/" } else { head }.to_owned())
}

/// The worktree root `git rev-parse --show-toplevel` prints for `cwd`: the
/// real directory holding the nearest `.git`, spelled without links, as Git
/// prints it. `None` when there is none, or when the first `.git` found is
/// anything Git could resolve to another root or refuse, which would leave
/// the substitution empty.
fn repository_root(cwd: &str) -> Option<String> {
    if GIT_DISCOVERY_VARIABLES
        .iter()
        .any(|name| std::env::var_os(name).is_some())
    {
        return None;
    }
    let start = std::fs::canonicalize(cwd).ok()?;
    // Inside a Git directory there is no worktree to print.
    if start.components().any(|part| part.as_os_str() == ".git") {
        return None;
    }
    let device = filesystem(&start)?;
    for directory in start.ancestors() {
        // Git stops looking at the edge of the starting filesystem.
        if filesystem(directory)? != device {
            return None;
        }
        let marker = directory.join(".git");
        let metadata = match std::fs::symlink_metadata(&marker) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        // The first `.git` decides. One this pass cannot prove Git reads as
        // this worktree keeps the value unknown, rather than walking past it
        // the way Git would walk past a directory it does not accept.
        let git_directory = if metadata.is_dir() {
            Some(marker)
        } else if metadata.is_file() {
            linked_git_directory(&marker, directory)
        } else {
            None
        };
        let git_directory = git_directory?;
        // Git refuses a repository another user owns (`safe.directory`).
        if !owned(directory) || !owned(&git_directory) || !plain_git_directory(&git_directory) {
            return None;
        }
        let root = directory.to_str()?.to_owned();
        return literal_path(&root).then_some(root);
    }
    None
}

/// The Git directory a `.git` file names with `gitdir: PATH`.
fn linked_git_directory(marker: &Path, directory: &Path) -> Option<std::path::PathBuf> {
    let text = small_file(marker)?;
    let target = text
        .strip_prefix("gitdir: ")?
        .trim_end_matches(['\n', '\r']);
    if target.is_empty() || target.contains('\n') {
        return None;
    }
    let target = directory.join(target);
    std::fs::symlink_metadata(&target)
        .is_ok_and(|metadata| metadata.is_dir())
        .then_some(target)
}

/// A Git directory with its own `HEAD` whose configuration cannot move or
/// blank the worktree root: no per-worktree configuration, and only
/// [`keeps_worktree`], in it and in the common directory a linked worktree
/// shares.
fn plain_git_directory(git_directory: &Path) -> bool {
    if !git_directory.join("HEAD").is_file() {
        return false;
    }
    let common = match std::fs::symlink_metadata(git_directory.join("commondir")) {
        Ok(_) => {
            let Some(text) = small_file(&git_directory.join("commondir")) else {
                return false;
            };
            let relative = text.trim_end_matches(['\n', '\r']);
            if relative.is_empty() || relative.contains('\n') {
                return false;
            }
            git_directory.join(relative)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => git_directory.to_path_buf(),
        Err(_) => return false,
    };
    if !common.join("objects").is_dir() || !common.join("refs").is_dir() {
        return false;
    }
    [git_directory, common.as_path()].iter().all(|base| {
        let absent = |name: &str| {
            std::fs::symlink_metadata(base.join(name))
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        };
        let path = base.join("config");
        absent("config.worktree")
            && (absent("config") || small_file(&path).is_some_and(|text| keeps_worktree(&text)))
    })
}

/// A configuration whose `core` keys are all ones that cannot move the
/// worktree root or make Git refuse it, with `bare` false and format version
/// 0, and with no include or extension. Other sections play no part in
/// finding the root. A line this reader cannot split the way Git does, such
/// as a continued value or a key after a section header, is refused.
fn keeps_worktree(text: &str) -> bool {
    let mut section = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.ends_with('\\') {
            return false;
        }
        if let Some(header) = line.strip_prefix('[') {
            let Some(header) = header.strip_suffix(']') else {
                return false;
            };
            let name = header
                .split([' ', '.'])
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            match name.as_str() {
                "include" | "includeif" | "extensions" => return false,
                "core" if !header.eq_ignore_ascii_case("core") => return false,
                _ => {}
            }
            section = Some(name);
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .map_or((line, "true"), |(key, value)| (key.trim(), value.trim()));
        match section.as_deref() {
            None => return false,
            Some("core") => {
                let known = match key.to_ascii_lowercase().as_str() {
                    "repositoryformatversion" => value == "0",
                    "bare" => value.eq_ignore_ascii_case("false"),
                    "filemode" | "logallrefupdates" | "ignorecase" | "precomposeunicode"
                    | "symlinks" => true,
                    _ => false,
                };
                if !known {
                    return false;
                }
            }
            Some(_) => {}
        }
    }
    true
}

/// Whether the current user owns `path`, as Git requires before it reads a
/// repository.
#[cfg(unix)]
fn owned(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).is_ok_and(|metadata| metadata.uid() == nix::unistd::geteuid().as_raw())
}

#[cfg(not(unix))]
fn owned(_: &Path) -> bool {
    false
}

/// The filesystem holding `path`.
#[cfg(unix)]
fn filesystem(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|metadata| metadata.dev())
}

#[cfg(not(unix))]
fn filesystem(_: &Path) -> Option<u64> {
    None
}

/// A regular file's text, when it is small and UTF-8.
fn small_file(path: &Path) -> Option<String> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_GIT_FILE_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// The text with every use outside single quotes and escapes replaced, the
/// index in that text just after the last replacement, and whether any use
/// must sit in a plain first step.
fn replace_uses(
    chars: &[char],
    extra: usize,
    mut found: impl FnMut(&[char]) -> Option<Option<Found>>,
) -> Option<(String, usize, bool)> {
    let mut out = String::with_capacity(chars.len() + extra);
    let mut last_use = None;
    let mut first_step = false;
    let mut single = false;
    let mut double = false;
    let mut index = 0usize;
    while index < chars.len() {
        let c = chars[index];
        if single {
            single = c != '\'';
            out.push(c);
            index += 1;
            continue;
        }
        let use_here = match c {
            '\'' if !double => {
                single = true;
                None
            }
            '"' => {
                double = !double;
                None
            }
            '\\' => {
                out.extend(chars.get(index..index + 2).unwrap_or(&chars[index..]));
                index += 2;
                continue;
            }
            '$' | '`' => found(&chars[index..])?,
            _ => None,
        };
        let Some((width, path, plain)) = use_here else {
            out.push(c);
            index += 1;
            continue;
        };
        out.push_str(&path);
        first_step |= plain;
        // Byte and character offsets agree: the text is ASCII.
        last_use = Some(out.len());
        index += width;
    }
    Some((out, last_use?, first_step))
}

/// The length and kind of a use at the start of `rest`; `Some(None)` when it
/// starts some other expansion, and `None` for a `$PWD` the shell would
/// subscript or modify (zsh's `$PWD[1]`, `$PWD:h`).
fn use_at(rest: &[char]) -> Option<Option<(usize, Use)>> {
    let starts = |text: &str| {
        rest.len() >= text.len() && rest.iter().zip(text.chars()).all(|(a, b)| *a == b)
    };
    if let Some(text) = PARENT_USES.iter().find(|text| starts(text)) {
        return Some(Some((text.len(), Use::Parent)));
    }
    if starts(TOPLEVEL_USE) {
        return Some(Some((TOPLEVEL_USE.len(), Use::Toplevel)));
    }
    if starts("$(pwd)") || starts("${PWD}") {
        return Some(Some((6, Use::Directory)));
    }
    if starts("`pwd`") {
        return Some(Some((5, Use::Directory)));
    }
    if starts("$PWD") {
        return match rest.get(4) {
            Some(c) if c.is_ascii_alphanumeric() || *c == '_' => Some(None),
            Some('[' | ':') => None,
            _ => Some(Some((4, Use::Directory))),
        };
    }
    Some(None)
}

#[cfg(test)]
#[path = "chain_literals_pwd_tests.rs"]
mod tests;
