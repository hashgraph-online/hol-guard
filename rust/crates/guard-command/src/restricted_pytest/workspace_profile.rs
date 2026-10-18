//! Seatbelt composition for `workspace-contained-v1`, kept apart from
//! `compose_macos_profile` so the existing profile bytes stay fixed.
use super::super::workspace_grant::GrantRules;
use super::*;
use crate::harness_config_names::{
    GITHUB_AGENT_DIRECTORIES, HARNESS_CONFIG_FILES, HARNESS_DIRECTORIES, HARNESS_INSTRUCTION_FILES,
};

/// Absolute names a sandboxed command must never execute; mirrors the
/// classifier's privilege exclusion so a shell cannot reach them by name.
const PRIVILEGE_NAMES: &[&str] = &[
    "sudo",
    "doas",
    "su",
    "login",
    "chmod",
    "chown",
    "chgrp",
    "chflags",
    "xattr",
    "setfacl",
    "launchctl",
    "crontab",
    "at",
    "security",
    "osascript",
    "open",
    "defaults",
    "dscl",
    "spctl",
    "csrutil",
    "kill",
    "killall",
    "pkill",
];
/// The libinfo endpoint Apple's own `system.sb` grants for user and group
/// lookups. Credential, keychain and directory-administration services stay
/// unreachable.
pub(super) const USER_DATABASE_SERVICE: &str = "com.apple.system.opendirectoryd.libinfo";
/// Root-level links (`/var` -> `/private/var`) that system tools name.
/// xcode-select reads `/var/select/developer_dir`; without metadata on the
/// link it fails with EPERM instead of falling back to its default.
const ROOT_LINKS: &[&str] = &["/etc", "/tmp", "/var"];
/// Configuration the granted toolchains read at startup: the developer
/// directory link, Xcode's license acceptance, Homebrew Git's system
/// config (which the classifier already evaluates for write denials), and
/// the OpenSSL config and CA bundles. Node and LibreSSL tools exit with an
/// OpenSSL configuration error when they cannot open their config.
const TOOLCHAIN_FILES: &[&str] = &[
    "/private/var/select/developer_dir",
    "/private/var/db/xcode_select_link",
    "/Library/Preferences/com.apple.dt.Xcode.plist",
    "/opt/homebrew/etc/gitconfig",
    "/usr/local/etc/gitconfig",
    "/opt/homebrew/etc/openssl@3/openssl.cnf",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/opt/homebrew/etc/ca-certificates/cert.pem",
    "/usr/local/etc/openssl@3/openssl.cnf",
    "/usr/local/etc/openssl@3/cert.pem",
    "/usr/local/etc/ca-certificates/cert.pem",
    "/private/etc/ssl/openssl.cnf",
    "/private/etc/ssl/cert.pem",
    "/System/Library/OpenSSL/openssl.cnf",
];
const PROTECTED_DIRECTORIES: &[&str] = &[
    ".bzr",
    ".hg",
    ".jj",
    ".pijul",
    ".svn",
    "_darcs",
    ".vscode",
    ".idea",
    ".devcontainer",
];

fn invalid() -> RestrictedPytestError {
    RestrictedPytestError::new(
        PYTEST_INVALID_COMMAND_REASON_CODE,
        "Invalid workspace sandbox request.",
    )
}

/// Case-insensitive regex for a literal. Specials become one-character
/// classes, so no backslash semantics are involved; the volume may be
/// case-insensitive, so letters match both cases.
fn ci(value: &str) -> Result<String, RestrictedPytestError> {
    let mut result = String::new();
    for c in value.chars() {
        match c {
            // `[^]` would open a negated class, so `^` is rejected outright.
            '\\' | '\n' | '\r' | '\0' | '^' => return Err(invalid()),
            c if c.is_ascii_alphabetic() => result.push_str(&format!(
                "[{}{}]",
                c.to_ascii_lowercase(),
                c.to_ascii_uppercase()
            )),
            '.' | '+' | '*' | '?' | '(' | ')' | '{' | '}' | '|' | '$' | '[' => {
                result.push('[');
                result.push(c);
                result.push(']');
            }
            ']' => result.push_str("[]]"),
            c => result.push(c),
        }
    }
    Ok(result)
}

fn alternatives(names: &[&str]) -> Result<String, RestrictedPytestError> {
    Ok(names
        .iter()
        .map(|name| ci(name))
        .collect::<Result<Vec<_>, _>>()?
        .join("|"))
}

/// Git execution configuration at any depth, so nested repositories are
/// covered. The trailing `?$` also denies creating, renaming or deleting the
/// `.git` entry itself, which blocks gitfile redirects and directory swaps.
pub(crate) fn git_exec_pattern(workspace: &Path) -> Result<String, RestrictedPytestError> {
    let root = ci(&workspace.to_string_lossy())?;
    let git = ci(".git")?;
    let config = format!("{}({}|{})?", ci("config")?, ci(".worktree")?, ci(".lock")?);
    let files = format!("{config}|{}|{}", ci("commondir")?, ci("gitdir")?);
    let trees = alternatives(&["hooks", "info", "modules", "worktrees", "objects/info"])?;
    Ok(format!(
        "^{root}/(.*/)?{git}(/({files})|/({trees})(/.*)?)?$"
    ))
}

/// A file named `HEAD` lets a later host Git take its directory for a bare
/// repository and load the `config` beside it, so none may be planted.
pub(crate) fn bare_head_pattern(root: &Path) -> Result<String, RestrictedPytestError> {
    Ok(format!(
        "^{}/(.*/)?{}$",
        ci(&root.to_string_lossy())?,
        ci("HEAD")?
    ))
}

/// Git keeps a `HEAD` in `.git/logs` (the reflog) and in each remote under
/// `.git/(logs/)?refs/remotes`. Adding `objects`, `commondir` or `config`
/// directly beside one would complete a bare repository there, so none may be
/// written. Deeper paths are ordinary refs, such as a branch named `fix/config`.
pub(crate) fn ref_store_repository_pattern(root: &Path) -> Result<String, RestrictedPytestError> {
    let config = format!("{}({}|{})?", ci("config")?, ci(".worktree")?, ci(".lock")?);
    let names = format!(
        "({config}|{}|{}|{})(/.*)?",
        ci("objects")?,
        ci("commondir")?,
        ci("gitdir")?
    );
    let (logs, refs, remotes) = (ci("logs")?, ci("refs")?, ci("remotes")?);
    Ok(format!(
        "^{}/(.*/)?{}/({logs}|({logs}/)?{refs}/{remotes}/[^/]+)/{names}$",
        ci(&root.to_string_lossy())?,
        ci(".git")?,
    ))
}

/// The directories under `.git` that hold such a `HEAD`, and those between
/// them and `.git`. Seatbelt checks only the paths an operation names, so
/// renaming one would carry its `HEAD` past `bare_head_pattern`. Denying
/// unlink still lets Git create them.
pub(super) fn head_carrier_pattern(root: &Path) -> Result<String, RestrictedPytestError> {
    let (logs, refs, remotes) = (ci("logs")?, ci("refs")?, ci("remotes")?);
    Ok(format!(
        "^{}/(.*/)?{}/({logs}(/{refs}(/{remotes}(/[^/]+)?)?)?|{refs}(/{remotes}(/[^/]+)?)?)$",
        ci(&root.to_string_lossy())?,
        ci(".git")?,
    ))
}

/// Version-control metadata, editor and devcontainer settings, and every
/// harness directory (plugins, hooks, settings, MCP and instruction files a
/// harness loads on its next start), at any depth.
pub(crate) fn protected_patterns(workspace: &Path) -> Result<Vec<String>, RestrictedPytestError> {
    let root = ci(&workspace.to_string_lossy())?;
    let directories: Vec<&str> = PROTECTED_DIRECTORIES
        .iter()
        .chain(HARNESS_DIRECTORIES)
        .copied()
        .collect();
    let files: Vec<&str> = HARNESS_CONFIG_FILES
        .iter()
        .chain(HARNESS_INSTRUCTION_FILES)
        .copied()
        .collect();
    let prefix = format!("^{root}/(.*/)?");
    let mut patterns = bounded(&prefix, &directories, "(/.*)?$")?;
    patterns.extend(bounded(&prefix, &files, "$")?);
    patterns.extend(bounded(
        &format!("{prefix}{}/", ci(".github")?),
        GITHUB_AGENT_DIRECTORIES,
        "(/.*)?$",
    )?);
    patterns.push(format!("{prefix}{}(/.*)?$", ci(".github/workflows")?));
    Ok(patterns)
}

/// Seatbelt rejects the whole profile when one string literal reaches about
/// 1,023 bytes, so long name lists are spread over as many rules as needed.
const SEATBELT_PATTERN_BUDGET: usize = 900;

/// Bytes `value` takes inside a Seatbelt string literal, after escaping.
fn quoted_len(value: &str) -> usize {
    value.len()
        + value
            .bytes()
            .filter(|byte| matches!(byte, b'\\' | b'"' | b'\n' | b'\r'))
            .count()
}

fn bounded(
    prefix: &str,
    names: &[&str],
    suffix: &str,
) -> Result<Vec<String>, RestrictedPytestError> {
    let mut patterns = Vec::new();
    let mut group: Vec<String> = Vec::new();
    let empty = quoted_len(prefix) + quoted_len(suffix) + 2;
    let mut length = empty;
    for name in names {
        let name = ci(name)?;
        let size = quoted_len(&name);
        if !group.is_empty() && length + 1 + size > SEATBELT_PATTERN_BUDGET {
            patterns.push(format!("{prefix}({}){suffix}", group.join("|")));
            group.clear();
            length = empty;
        }
        // A name that does not fit in an empty group cannot be split further.
        if length + size > SEATBELT_PATTERN_BUDGET {
            return Err(invalid());
        }
        length += size + usize::from(!group.is_empty());
        group.push(name);
    }
    if !group.is_empty() {
        patterns.push(format!("{prefix}({}){suffix}", group.join("|")));
    }
    Ok(patterns)
}

/// Helper paths stay unwritable at any letter case, and so does every
/// directory between the workspace and each of them. Seatbelt checks only
/// the paths an operation names, so otherwise a command could rename an
/// ancestor away and put a symlink to its own files in its place.
pub(super) fn denial_patterns(
    workspace: &Path,
    denials: &[PathBuf],
) -> Result<Vec<String>, RestrictedPytestError> {
    let mut patterns = Vec::new();
    for denial in denials {
        if !denial.starts_with(workspace) || denial == workspace {
            return Err(invalid());
        }
        patterns.push(format!("^{}(/.*)?$", ci(&denial.to_string_lossy())?));
        let mut ancestor = denial.parent();
        while let Some(directory) = ancestor.filter(|directory| *directory != workspace) {
            let pattern = format!("^{}$", ci(&directory.to_string_lossy())?);
            if !patterns.contains(&pattern) {
                patterns.push(pattern);
            }
            ancestor = directory.parent();
        }
    }
    Ok(patterns)
}

/// The network a run's inline Node source needs when it serves and fetches
/// only on literal loopback ports, derived again from the exact command
/// about to run: each port may be bound, accepted on and connected to on
/// the loopback address. Every other address stays denied by default.
pub(super) fn loopback_rules(ports: &[u16]) -> Vec<String> {
    ports
        .iter()
        .flat_map(|port| {
            [
                format!("(allow network-bind (local ip \"localhost:{port}\"))"),
                format!("(allow network-inbound (local ip \"localhost:{port}\"))"),
                format!("(allow network-outbound (remote ip \"localhost:{port}\"))"),
            ]
        })
        .collect()
}

fn regex_rule(operations: &str, pattern: &str) -> String {
    format!("(deny {operations} (regex {}))", seatbelt_string(pattern))
}

pub(super) fn compose(
    input: &Input,
    system_roots: &[PathBuf],
    files: &[PathBuf],
) -> Result<String, RestrictedPytestError> {
    compose_with(input, system_roots, files, &GrantRules::default())
}

/// `compose` plus a local CLI grant's checked rules, which never follow the
/// credential denials.
pub(super) fn compose_with(
    input: &Input,
    system_roots: &[PathBuf],
    files: &[PathBuf],
    grant: &GrantRules,
) -> Result<String, RestrictedPytestError> {
    let workspace = &input.workspace;
    if !workspace.is_absolute() || !input.private_root.is_absolute() {
        return Err(invalid());
    }
    let linked = input
        .linked_git
        .as_ref()
        .map(|linked| linked.checked(workspace))
        .transpose()?;
    // The only read grants a workspace run takes beyond the system and its
    // toolchain are scripts the command launches, each one regular file.
    let mut scripts = input
        .read_only_roots
        .iter()
        .filter(|r| !grant.reads.contains(*r));
    if scripts.any(|root| {
        !root.is_absolute()
            || root.starts_with(workspace)
            || !std::fs::symlink_metadata(root).is_ok_and(|meta| meta.file_type().is_file())
            || root.canonicalize().ok().as_deref() != Some(root.as_path())
            || root.to_str().is_none_or(|text| {
                crate::secret_path_probe::is_request_secret_path(text, None, None)
            })
    }) {
        return Err(invalid());
    }
    let mut extra_reads = existing(&[
        "/bin",
        "/usr/bin",
        "/private/var/select",
        "/private/var/db/timezone",
    ]);
    extra_reads.extend(input.exec_roots.iter().cloned());
    extra_reads.extend(input.read_only_roots.iter().cloned());
    let mut writable = vec![workspace.clone(), input.private_root.clone()];
    writable.extend(grant.writes.iter().cloned());
    let mut roots = vec![workspace.clone(), input.private_root.clone()];
    roots.extend(linked.map(|linked| linked.checkout().to_path_buf()));
    roots.extend_from_slice(system_roots);
    roots.extend(extra_reads.iter().cloned());
    let mut metadata = vec![PathBuf::from("/")];
    metadata.extend(ancestor_paths(&roots));
    // Bun's resolver lists every directory above the working directory while
    // it looks for project files and fails outright when it cannot. A listing
    // shows names, never contents, and the credential denials below still
    // cover any ancestor they name.
    let mut listed: Vec<PathBuf> = workspace
        .ancestors()
        .skip(1)
        .map(Path::to_path_buf)
        .collect();
    if listed.is_empty() {
        listed.push(PathBuf::from("/"));
    }
    metadata.extend(existing(ROOT_LINKS));
    let mut files = files.to_vec();
    files.extend(existing(TOOLCHAIN_FILES));
    // A toolchain that links a binary and then runs it — `go test`, a cgo
    // build, a compiled test runner — writes it into the private directory
    // the plan gives the run for temporary files. That directory is the run's
    // own and already writable, as the workspace is, and the workspace is
    // executable too, so running what this command itself just built reaches
    // nothing the command could not already run.
    let mut executable = vec![workspace.clone(), input.private_root.clone()];
    executable.extend(linked.map(|linked| linked.checkout().to_path_buf()));
    executable.extend(existing(&["/bin", "/usr/bin"]));
    executable.extend(input.exec_roots.iter().cloned());
    let privileged: Vec<PathBuf> = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        .iter()
        .flat_map(|dir| {
            PRIVILEGE_NAMES
                .iter()
                .map(move |name| Path::new(dir).join(name))
        })
        .collect();
    let mut lines = vec![
        "(version 1)".to_owned(),
        "(deny default)".to_owned(),
        "(deny file-link)".to_owned(),
        "(allow process-fork)".to_owned(),
        format!("(allow process-exec {})", filter(&executable, "subpath")),
        format!("(deny process-exec {})", filter(&privileged, "literal")),
        "(allow signal (target self) (target children))".to_owned(),
        "(allow sysctl-read)".to_owned(),
        // `getpwuid`, `getgrgid` and `getgrouplist` reach the user database
        // through this one opendirectoryd endpoint; without it `id`, Python's
        // `pwd`, Go's `os/user`, ssh and git cannot name the current user.
        // It answers the same account queries any process can make, and no
        // other mach service is reachable.
        format!("(allow mach-lookup (global-name \"{USER_DATABASE_SERVICE}\"))"),
        format!("(allow file-read-data {})", filter(&listed, "literal")),
        format!(
            "(allow file-read-metadata {})",
            filter(&metadata, "literal")
        ),
        format!(
            "(allow file-read* {} {})",
            filter(&roots, "subpath"),
            filter(&files, "literal")
        ),
        format!(
            "(allow file-write* {} (literal \"/dev/null\"))",
            filter(&writable, "subpath")
        ),
        // Moving the workspace itself would put it beyond every rule below.
        format!(
            "(deny file-write* {})",
            filter(std::slice::from_ref(workspace), "literal")
        ),
    ];
    let mut repositories: Vec<&Path> = vec![workspace, &input.private_root];
    if let Some(linked) = linked {
        // A linked worktree's objects, refs and reflogs live in the main
        // checkout's `.git`, which its rules below cover as well.
        let (shared, _) = linked.files();
        let trees = linked.shared_trees();
        lines.push(format!(
            "(allow file-write* {} {})",
            filter(&trees, "subpath"),
            filter(&shared, "literal")
        ));
        let mut fixed = trees;
        fixed.push(linked.common.clone());
        lines.push(format!("(deny file-write* {})", filter(&fixed, "literal")));
        repositories.push(linked.checkout());
    }
    // Seatbelt checks only the paths an operation names, so a repository or
    // protected file built or edited in the private root could be moved into
    // the workspace. Both roots therefore get the same rules.
    for root in repositories {
        lines.push(regex_rule("file-write*", &git_exec_pattern(root)?));
        lines.push(regex_rule("file-write*", &bare_head_pattern(root)?));
        lines.push(regex_rule(
            "file-write*",
            &ref_store_repository_pattern(root)?,
        ));
        lines.push(regex_rule(
            "file-write-unlink",
            &head_carrier_pattern(root)?,
        ));
        for pattern in protected_patterns(root)? {
            lines.push(regex_rule("file-write*", &pattern));
        }
    }
    // The repository's own `HEAD`, which checkout and branch switches
    // rewrite, and its reflog, which every commit appends to.
    lines.push(format!(
        "(allow file-write* {})",
        filter(
            &[
                workspace.join(".git/HEAD"),
                workspace.join(".git/logs/HEAD")
            ],
            "literal"
        )
    ));
    if let Some(linked) = linked {
        lines.push(format!(
            "(allow file-write* {})",
            filter(&linked.files().1, "literal")
        ));
        // Its reflog directory holds a `HEAD`. Renaming it into a shared
        // tree would carry that `HEAD` past `bare_head_pattern`, so, as with
        // `head_carrier_pattern`, Git may create it but not move it.
        lines.push(format!(
            "(deny file-write-unlink {})",
            filter(&[linked.admin.join("logs")], "literal")
        ));
    }
    for pattern in denial_patterns(workspace, &input.write_denials)? {
        lines.push(regex_rule("file-write*", &pattern));
    }
    // The daemon's state is read again here, at launch: the port it settled
    // on may have changed since the command was judged.
    let home = std::env::var("HOME").ok();
    lines.extend(loopback_rules(&crate::pretool::launch_loopback_ports(
        &input.command,
        input.cwd.to_str(),
        home.as_deref(),
    )));
    lines.extend(grant.network.iter().cloned());
    // Last, so no earlier allow can reopen a credential for reading or writing.
    for pattern in patterns() {
        lines.push(regex_rule("file-read* file-write*", &pattern));
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_that_cannot_fit_in_a_fresh_group_is_rejected() {
        let long = "n".repeat(SEATBELT_PATTERN_BUDGET);
        assert!(bounded("^", &["ok", &long], "$").is_err());
        assert!(bounded("^", &["hooks", "plugins"], "$").is_ok());
    }
}
