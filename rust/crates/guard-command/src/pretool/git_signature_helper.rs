//! Whether the program a signature check would start is one the user chose.
//!
//! `--show-signature`, a `%G` placeholder, `log.showSignature` or a pretty
//! alias carrying `%G` makes Git start a verification program for each signed
//! commit it prints. The signature's own format picks the program:
//! `gpg.openpgp.program` or `gpg.program` (default `gpg`), `gpg.x509.program`
//! (default `gpgsm`) or `gpg.ssh.program` (default `ssh-keygen`).
//!
//! The read is cleared only when every `gpg.*` setting Git would read comes
//! from the user's own or the system configuration, so neither the
//! repository nor the command line chose what runs or what it reads, and
//! every program Git could start is either missing from the search path or
//! installed in a trusted location. A setting the repository, a worktree or a
//! `-c` option supplies keeps the review, as does a program under the home
//! directory, the working directory or a temporary directory.

use std::path::Path;
use std::process::Command;
use std::time::Instant;

const SCOPE_LIMIT: u64 = 65_536;

const PROGRAM_KEYS: [(&str, &str); 4] = [
    ("gpg.program", "gpg"),
    ("gpg.openpgp.program", "gpg"),
    ("gpg.x509.program", "gpgsm"),
    ("gpg.ssh.program", "ssh-keygen"),
];

pub(super) fn user_chosen(
    command: &Command,
    home: &Path,
    cwd: &Path,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    deadline: Instant,
) -> bool {
    let Some(mut query) = super::git_probe::copy_command(command) else {
        return false;
    };
    let output = match super::git_probe::output_bounded(
        query.args([
            "--no-pager",
            "config",
            "--null",
            "--show-scope",
            "--get-regexp",
            "^gpg\\.",
        ]),
        deadline,
        SCOPE_LIMIT,
    ) {
        super::git_probe::Bounded::Completed(status, output) if status.success() => output,
        super::git_probe::Bounded::Completed(status, output)
            if status.code() == Some(1) && output.is_empty() =>
        {
            Vec::new()
        }
        _ => return false,
    };
    let Some(programs) = user_programs(&output) else {
        return false;
    };
    let Some(search_path) = search_path(execution_environment) else {
        return false;
    };
    programs.iter().all(|program| {
        super::git_config_trust::trusted_command(program, home, cwd, execution_environment)
            .is_some()
            || (Path::new(program).components().count() == 1
                && !on_search_path(program, &search_path))
    })
}

/// The programs a signature check could start, or nothing when a `gpg.*`
/// setting comes from anywhere but the user's or the system configuration.
/// `git config --null --show-scope` writes each entry as its scope, a NUL,
/// the key, a newline, the value and a NUL; a key written with no value
/// carries no newline.
fn user_programs(output: &[u8]) -> Option<Vec<String>> {
    let output = std::str::from_utf8(output).ok()?;
    if !output.is_empty() && !output.ends_with('\0') {
        return None;
    }
    let mut fields = output.split('\0');
    let mut programs = Vec::new();
    let mut configured = [false; PROGRAM_KEYS.len()];
    while let Some(scope) = fields.next() {
        if scope.is_empty() {
            // Only the empty tail after the final NUL ends the reply.
            if fields.next().is_some() {
                return None;
            }
            break;
        }
        let record = fields.next()?;
        if !matches!(scope, "global" | "system") {
            return None;
        }
        let Some((key, value)) = record.split_once('\n') else {
            // A program key with no value is no program Git can start, and
            // any other bare `gpg.*` key is a switch, not a program.
            if PROGRAM_KEYS.iter().any(|(name, _)| *name == record) {
                return None;
            }
            continue;
        };
        if let Some(index) = PROGRAM_KEYS.iter().position(|(name, _)| *name == key) {
            let program = Path::new(value);
            // Git looks a relative path up from the directory it runs in,
            // which a `-C` route moves away from the working directory.
            if value.is_empty() || !program.is_absolute() && program.components().count() != 1 {
                return None;
            }
            configured[index] = true;
            programs.push(value.to_owned());
        }
    }
    // `gpg.program` and `gpg.openpgp.program` name the same program.
    let openpgp = configured[0] || configured[1];
    for (default, set) in [
        ("gpg", openpgp),
        ("gpgsm", configured[2]),
        ("ssh-keygen", configured[3]),
    ] {
        if !set {
            programs.push(default.to_owned());
        }
    }
    Some(programs)
}

/// The search path a bare program name is looked up on. A relative entry is
/// read from the directory Git runs in, which a `-C` route moves, so such a
/// path proves nothing about what a bare name starts.
fn search_path(
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<Vec<std::path::PathBuf>> {
    let path = execution_environment
        .map(|context| std::ffi::OsString::from(&context.path))
        .or_else(|| std::env::var_os("PATH"))?;
    let entries = std::env::split_paths(&path).collect::<Vec<_>>();
    entries
        .iter()
        .all(|entry| entry.is_absolute())
        .then_some(entries)
}

fn on_search_path(program: &str, search_path: &[std::path::PathBuf]) -> bool {
    let names = if cfg!(windows) {
        ["", ".exe", ".com", ".bat", ".cmd"]
            .iter()
            .map(|extension| format!("{program}{extension}"))
            .collect::<Vec<_>>()
    } else {
        vec![program.to_owned()]
    };
    search_path.iter().any(|directory| {
        names
            .iter()
            .any(|name| std::fs::symlink_metadata(directory.join(name)).is_ok())
    })
}

#[cfg(test)]
#[path = "git_signature_helper_tests.rs"]
mod tests;
