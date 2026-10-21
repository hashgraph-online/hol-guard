//! Where Git for Windows reads configuration a read-only git could act on.
//!
//! The system files sit in the install that holds the bound `git.exe`, not at
//! `/etc/gitconfig`, and git finds the user files from `HOME`, then
//! `HOMEDRIVE` + `HOMEPATH`, then `USERPROFILE`. The shell git runs from may
//! pick any of those, so every home Guard can see is a candidate, and one it
//! cannot pin to a drive-rooted path leaves the read once-only.

use super::context::Ctx;
use super::fs_path;
use super::git_config::Found;
use super::launch_windows::{env_value, under_install_root};
use super::reasons::{Proof, GIT_HELPER_CONFIG, UNPROVEN_LAUNCH};

/// The MSYS2 environments a Git for Windows install ships its tools under.
const ARCH_DIRS: [&str; 3] = ["mingw64", "mingw32", "clangarm64"];
/// `git log` options that print no diff, so no text converter runs.
const PLAIN_LOG_OPTIONS: [&str; 8] = [
    "--oneline",
    "--graph",
    "--decorate",
    "--no-decorate",
    "--all",
    "--reverse",
    "--no-color",
    "--first-parent",
];
const PLAIN_LOG_PREFIXES: [&str; 3] = ["--max-count=", "--format=", "--pretty="];
/// `git status` options that leave the verbose diff off. Status takes any
/// unique abbreviation (`--verb`), so only these exact spellings count.
const PLAIN_STATUS_OPTIONS: [&str; 14] = [
    "--short",
    "--branch",
    "--porcelain",
    "--porcelain=v1",
    "--porcelain=v2",
    "--long",
    "--show-stash",
    "--null",
    "--ignored",
    "--renames",
    "--no-renames",
    "--untracked-files=no",
    "--untracked-files=normal",
    "--untracked-files=all",
];
/// Subcommands that hash worktree files, which runs the clean filter.
const WORKTREE_READERS: [&str; 3] = ["status", "diff", "ls-files"];
const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;

/// The system config and attribute files of the install holding `git`.
///
/// Only the launcher layouts Git for Windows installs (`cmd\git.exe`,
/// `bin\git.exe`, `<arch>\bin\git.exe`) under an administrator-owned install
/// root are known; any other copy of git could read files this proof does
/// not list.
pub(super) fn system_files(git: &str, ctx: &Ctx) -> Proof<Vec<String>> {
    let bin = fs_path::parent(git);
    let above = fs_path::parent(&bin);
    let above_name = fs_path::name(&above).to_ascii_lowercase();
    let root = match fs_path::name(&bin).to_ascii_lowercase().as_str() {
        "cmd" => above,
        "bin" if ARCH_DIRS.contains(&above_name.as_str()) => fs_path::parent(&above),
        "bin" => above,
        _ => return Err(UNPROVEN_LAUNCH),
    };
    if !under_install_root(&root) {
        return Err(UNPROVEN_LAUNCH);
    }
    let mut files = vec![
        fs_path::join(&root, "etc\\gitconfig"),
        fs_path::join(&root, "etc\\gitattributes"),
    ];
    for arch in ARCH_DIRS {
        let prefix = fs_path::join(&root, arch);
        if fs_path::is_dir(&prefix) {
            files.push(fs_path::join(&prefix, "etc\\gitconfig"));
            files.push(fs_path::join(&prefix, "etc\\gitattributes"));
        }
    }
    if let Some(data) = env_value(ctx.env, "PROGRAMDATA")? {
        files.push(fs_path::join(&drive_rooted(data)?, "Git\\config"));
    }
    Ok(files)
}

/// `XDG_CONFIG_HOME` and every home git may resolve, each drive-rooted.
pub(super) fn user_config_roots(ctx: &Ctx) -> Proof<(Option<String>, Vec<String>)> {
    let xdg = match env_value(ctx.env, "XDG_CONFIG_HOME")? {
        Some(value) if !value.is_empty() => Some(drive_rooted(value)?),
        _ => None,
    };
    let mut homes: Vec<String> = Vec::new();
    let joined = match (
        env_value(ctx.env, "HOMEDRIVE")?,
        env_value(ctx.env, "HOMEPATH")?,
    ) {
        (Some(drive), Some(path)) if !drive.is_empty() && !path.is_empty() => {
            Some(format!("{drive}{path}"))
        }
        _ => None,
    };
    let named = [
        ctx.home.map(str::to_owned),
        env_value(ctx.env, "HOME")?.map(str::to_owned),
        joined,
        env_value(ctx.env, "USERPROFILE")?.map(str::to_owned),
    ];
    for home in named.into_iter().flatten().filter(|home| !home.is_empty()) {
        let home = drive_rooted(&home)?;
        if !homes.iter().any(|seen| seen.eq_ignore_ascii_case(&home)) {
            homes.push(home);
        }
    }
    Ok((xdg, homes))
}

/// An include or hooks path git resolves the way this proof does: drive-rooted,
/// or relative to the including file. `~` follows git's own `HOME`, and a
/// rooted, drive-relative or `%(prefix)` spelling follows the install or a
/// per-drive cwd.
pub(super) fn config_reference_is_pinned(value: &str) -> bool {
    fs_path::is_abs(value)
        || !(fs_path::is_anchored(value) || value.starts_with(['~', '%', '/', '\\']))
}

fn drive_rooted(value: &str) -> Proof<String> {
    if fs_path::is_abs(value) {
        Ok(fs_path::norm(value))
    } else {
        Err(UNPROVEN_LAUNCH)
    }
}

/// A git dir git itself takes: `HEAD`, with `objects` and `refs` in the
/// common dir. Git walks past a `.git` directory without them, and a
/// `commondir` in one points config and hooks elsewhere, so either leaves
/// the read once-only.
pub(super) fn git_dir_is_plain(git_dir: &str, common_dir: &str, directory: bool) -> Proof<()> {
    let redirected = directory && exists(&fs_path::join(git_dir, "commondir"));
    let valid = fs_path::is_file(&fs_path::join(git_dir, "HEAD"))
        && fs_path::is_dir(&fs_path::join(common_dir, "objects"))
        && fs_path::is_dir(&fs_path::join(common_dir, "refs"));
    match valid && !redirected {
        true => Ok(()),
        false => Err(UNPROVEN_LAUNCH),
    }
}

/// Shaped enough like a repository that git, which checks each directory
/// for a bare repository before it looks further up, could take it as one.
pub(super) fn may_be_git_dir(dir: &str) -> bool {
    exists(&fs_path::join(dir, "HEAD"))
        && ["objects", "refs", "commondir"]
            .iter()
            .any(|name| exists(&fs_path::join(dir, name)))
}

fn exists(path: &str) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Git for Windows runs `astextplain` (and the converters it calls) and
/// `git-lfs` through a `PATH` lookup the digest cannot bind, and a child git
/// for each populated submodule with config, hooks and attributes the digest
/// never reads, so a reusable invocation must never start one: no submodule
/// in the index or the arguments, no text conversion while the `astextplain`
/// driver is configured, and no worktree hashing while the LFS filter is
/// configured and an attribute could route a path to it.
pub(super) fn helpers_stay_idle(
    found: &Found,
    invocation: &[String],
    root: &str,
    git_dir: &str,
) -> Proof<()> {
    let (subcommand, rest) = invocation.split_first().ok_or(GIT_HELPER_CONFIG)?;
    let entries = index_entries(git_dir)?;
    let names_submodule = invocation
        .iter()
        .any(|argument| argument.to_ascii_lowercase().contains("submodule"));
    if names_submodule
        || entries
            .iter()
            .any(|entry| entry.mode & 0o170000 == 0o160000)
    {
        return Err(GIT_HELPER_CONFIG);
    }
    if found.astextplain && may_textconv(subcommand, rest) {
        return Err(GIT_HELPER_CONFIG);
    }
    let hashes_worktree = found.lfs_filter && WORKTREE_READERS.contains(&subcommand.as_str());
    if hashes_worktree
        && (found.attributes_name_lfs || index_supplies_attributes(root, &entries, &found.unwalked))
    {
        return Err(GIT_HELPER_CONFIG);
    }
    Ok(())
}

/// Whether a read-only invocation can print a diff, which text-converts.
fn may_textconv(subcommand: &str, rest: &[String]) -> bool {
    // Options end at `--`; every argument past it is a path.
    let end = rest
        .iter()
        .position(|argument| argument == "--")
        .unwrap_or(rest.len());
    let options = || {
        rest[..end]
            .iter()
            .filter(|argument| argument.starts_with('-'))
    };
    // The last textconv toggle wins (`--no-textconv --textconv` converts).
    let no_textconv = options()
        .rfind(|option| option.starts_with("--textc") || option.starts_with("--no-textc"))
        .is_some_and(|option| option == "--no-textconv");
    match subcommand {
        "status" => !options().all(|option| {
            PLAIN_STATUS_OPTIONS.contains(&option.as_str())
                || (!option.starts_with("--") && !option.contains('v'))
        }),
        "log" if no_textconv => false,
        "log" => !options().all(|option| {
            PLAIN_LOG_OPTIONS.contains(&option.as_str())
                || PLAIN_LOG_PREFIXES
                    .iter()
                    .any(|prefix| option.starts_with(prefix))
                || (option.len() > 1 && option[1..].bytes().all(|byte| byte.is_ascii_digit()))
        }),
        "rev-parse" | "ls-files" | "branch" | "remote" | "worktree" => false,
        _ => !no_textconv,
    }
}

/// Whether git could take attributes the digest never read: from an indexed
/// `.gitattributes` whose worktree copy is missing or skip-worktree, or from
/// one inside a folder the attribute walk skipped (`unwalked`) that holds a
/// tracked path. Git opens an index name as spelled, so once a folder is
/// skipped a name a lowercase prefix may not match (a short name, a trimmed
/// trailing dot or space, a non-ASCII case fold) counts as inside it.
fn index_supplies_attributes(root: &str, entries: &[IndexEntry], unwalked: &[String]) -> bool {
    entries.iter().any(|entry| {
        let name = entry.name.to_ascii_lowercase();
        let attributes = (name == ".gitattributes" || name.ends_with("/.gitattributes"))
            && (entry.extended || !fs_path::is_file(&fs_path::join(root, &name)));
        let skipped = !unwalked.is_empty()
            && (unwalked
                .iter()
                .any(|prefix| name.starts_with(prefix.as_str()))
                || !name.split('/').all(compares_as_spelled));
        attributes || skipped
    })
}

fn compares_as_spelled(part: &str) -> bool {
    part.is_ascii() && !part.contains(['~', ':', '\\']) && !part.ends_with(['.', ' '])
}

struct IndexEntry {
    name: String,
    mode: u32,
    extended: bool,
}

/// The entries of the index. An index this parser cannot read (version 4,
/// SHA-256, a split or sparse index, damaged) fails closed.
fn index_entries(git_dir: &str) -> Proof<Vec<IndexEntry>> {
    let path = fs_path::join(git_dir, "index");
    if !fs_path::is_file(&path) {
        return Ok(Vec::new());
    }
    let data = fs_path::read_bounded(&path, MAX_INDEX_BYTES).ok_or(UNPROVEN_LAUNCH)?;
    let word = |at: usize| {
        data.get(at..at + 4)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            .ok_or(UNPROVEN_LAUNCH)
    };
    let version = word(4)?;
    if !data.starts_with(b"DIRC") || !(2..=3).contains(&version) {
        return Err(UNPROVEN_LAUNCH);
    }
    let mut entries = Vec::new();
    let mut at = 12;
    for _ in 0..word(8)? {
        let flags = data
            .get(at + 60..at + 62)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
            .ok_or(UNPROVEN_LAUNCH)?;
        let extended = flags & 0x4000 != 0;
        let start = at + if extended { 64 } else { 62 };
        let length = data
            .get(start..)
            .and_then(|rest| rest.iter().position(|byte| *byte == 0))
            .ok_or(UNPROVEN_LAUNCH)?;
        if (extended && version < 3) || usize::from(flags & 0xFFF) != length.min(0xFFF) {
            return Err(UNPROVEN_LAUNCH);
        }
        let name =
            std::str::from_utf8(&data[start..start + length]).map_err(|_| UNPROVEN_LAUNCH)?;
        entries.push(IndexEntry {
            name: name.to_owned(),
            mode: word(at + 24)?,
            extended,
        });
        at += (start - at + length + 8) & !7;
    }
    // Extensions follow, then the SHA-1. A split (`link`) or sparse (`sdir`)
    // index keeps entries elsewhere; like every extension git must not
    // ignore, its signature starts lowercase.
    let end = data.len().checked_sub(20).ok_or(UNPROVEN_LAUNCH)?;
    while at < end {
        let optional = data.get(at).is_some_and(u8::is_ascii_uppercase);
        let size = usize::try_from(word(at + 4)?).map_err(|_| UNPROVEN_LAUNCH)?;
        at = at
            .checked_add(8)
            .and_then(|body| body.checked_add(size))
            .filter(|next| optional && *next <= end)
            .ok_or(UNPROVEN_LAUNCH)?;
    }
    match at == end {
        true => Ok(entries),
        false => Err(UNPROVEN_LAUNCH),
    }
}
