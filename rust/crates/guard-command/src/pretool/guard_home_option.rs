//! A `--home` option that names the Guard home the command already uses.
//!
//! Guard's inspection commands read the store under their home. Without
//! `--home` that is the account's own `.hol-guard` directory, once it exists
//! and no home left by an older release sits beside it. Another home is one
//! the command may create or that holds someone else's state, so root
//! overrides stay under review. A `--home` that spells that same directory
//! as an absolute path reads the store the plain command reads, so it is set
//! aside before the subcommand is checked: `hol-guard approvals wait <id>
//! --home /Users/me/.hol-guard` is proven the way `hol-guard approvals wait
//! <id>` is.
//!
//! The Guard home the hook reported for this request is set aside the same
//! way. It is the store this decision is made against, so a `--home` naming
//! it reads nothing the hook does not already use. When that home is not the
//! account's default, the wait command Guard prints for a held request names
//! it, and an agent that runs the printed command must not be held again.

/// [`super::guard_diagnostics::safe_hol_guard_segment`] for `segment`, read
/// once as written and once more with a `--home` naming the account's own
/// Guard home set aside.
pub(super) fn safe_hol_guard_segment(
    basename: &str,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    let proven = |arguments: &[String]| {
        super::guard_diagnostics::safe_hol_guard_segment(
            basename,
            arguments,
            context.cwd,
            segment.pipeline_index,
        )
    };
    // A Windows .cmd launcher reparses the *original* argument words. A
    // trusted --home word must not be removed before this check, or shell
    // operators in the home path could be hidden from the reachability proof.
    let arguments_reach_launcher = super::guard_diagnostics::arguments_reach_the_launcher(
        basename,
        &segment.arguments,
        cfg!(windows),
    );
    proven(&segment.arguments)
        || (arguments_reach_launcher
            && (without_own_home(&segment.arguments, context.home_dir)
                .is_some_and(|rest| proven(&rest))
                || without_active_home(&segment.arguments, context.guard_home)
                    .is_some_and(|rest| proven(&rest))))
}

/// Home directories older releases kept Guard's state in, beside the user's
/// home. When one exists the launcher may still resolve to it, or move it
/// into `.hol-guard` on its next start (`guard_home_resolve` in the runtime
/// crate), so a `--home` naming `.hol-guard` is not proven to be the home it
/// uses.
const LEGACY_DIRNAMES: [&str; 3] = [
    ".config/.ai-plugin-scanner-guard",
    ".ai-plugin-scanner-guard",
    ".holguard",
];

/// `arguments` without their one `--home` option, when that option names the
/// Guard home the launcher uses without it: `.hol-guard` under the account's
/// home, which already exists, with no legacy home beside it. `None` when
/// there is no such option, when it names any other directory, or when it is
/// given more than once.
pub(super) fn without_own_home(
    arguments: &[String],
    home_dir: Option<&str>,
) -> Option<Vec<String>> {
    let home = normal_home(home_dir?)?;
    let own = format!("{home}/.hol-guard");
    let launcher_home = std::path::Path::new(&own).is_dir()
        && !LEGACY_DIRNAMES
            .iter()
            .any(|legacy| std::path::Path::new(&format!("{home}/{legacy}")).exists());
    if !launcher_home {
        return None;
    }
    without_home_option(arguments, &own)
}

/// `arguments` without their one `--home` option, when that option names the
/// Guard home the hook reported for this request and that directory exists.
/// `None` when there is no reported home, no such option, when it names any
/// other directory, or when it is given more than once.
pub(super) fn without_active_home(
    arguments: &[String],
    guard_home: Option<&str>,
) -> Option<Vec<String>> {
    let active = normal_home(guard_home?)?;
    if !std::path::Path::new(&active).is_dir() {
        return None;
    }
    without_home_option(arguments, &active)
}

/// The account's home as an absolute path with `/` separators and no
/// trailing one: a POSIX path, or a Windows drive path whose `\` separators
/// are rewritten. `None` for anything else.
fn normal_home(home: &str) -> Option<String> {
    let home = if drive_path(home) {
        home.replace('\\', "/")
    } else if home.starts_with('/') {
        home.to_owned()
    } else {
        return None;
    };
    let home = home.trim_end_matches('/');
    (!home.is_empty() && !home.ends_with(':')).then(|| home.to_owned())
}

fn drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

/// `arguments` without their one `--home` option when it names `own`. A
/// Windows drive path matches with either separator and in any letter case,
/// as Windows resolves it.
fn without_home_option(arguments: &[String], own: &str) -> Option<Vec<String>> {
    let same = |value: &str| {
        if drive_path(own) {
            drive_path(value)
                && value
                    .replace('\\', "/")
                    .trim_end_matches('/')
                    .eq_ignore_ascii_case(own)
        } else {
            value.trim_end_matches('/') == own
        }
    };
    let mut rest = Vec::with_capacity(arguments.len());
    let mut found = false;
    let mut words = arguments.iter();
    while let Some(word) = words.next() {
        let value = if word == "--home" {
            words.next()?.as_str()
        } else if let Some(value) = word.strip_prefix("--home=") {
            value
        } else {
            rest.push(word.clone());
            continue;
        };
        if found || !same(value) {
            return None;
        }
        found = true;
    }
    found.then_some(rest)
}

/// Whether `command` is Guard's own approval inspection on the Guard home
/// the hook itself reports: one plain `hol-guard approvals`, `approvals list`,
/// `approvals wait <id>` or `approvals retry-hint <id>`, optionally with one
/// `--home` naming `guard_home`. This is the wait Guard tells the agent to
/// run after a review, `hol-guard approvals wait <id> --json --home <home>`,
/// so it reads only the store that review was queued in.
///
/// The runtime uses this to keep a policy floor such as
/// `subprocess_action: review` from holding Guard's own instructions for a
/// review behind a second review.
pub fn guard_approval_inspection_command(
    command: &str,
    guard_home: &str,
    cwd: Option<&str>,
) -> bool {
    let Ok(model) = crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }) else {
        return false;
    };
    if model.confidence != "exact"
        || model.uncertainty_reason.is_some()
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
    {
        return false;
    }
    let [segment] = model.segments.as_slice() else {
        return false;
    };
    let Some(executable) = segment.executable.as_deref() else {
        return false;
    };
    if !matches!(executable, "hol-guard" | "hol-guard.exe")
        || segment.pipeline_index != 0
        || !segment.environment_names.is_empty()
        || !segment.wrapper_chain.is_empty()
        || segment.path_overridden
        || segment.tokens.len() != segment.arguments.len() + 1
    {
        return false;
    }
    // A Windows .cmd launcher reparses the original words, so the --home
    // word is checked before it is set aside.
    if !super::guard_diagnostics::arguments_reach_the_launcher(
        executable,
        &segment.arguments,
        cfg!(windows),
    ) {
        return false;
    }
    let names_home = segment
        .arguments
        .iter()
        .any(|word| word == "--home" || word.starts_with("--home="));
    let arguments = if names_home {
        let Some(own) = normal_home(guard_home) else {
            return false;
        };
        let Some(rest) = without_home_option(&segment.arguments, &own) else {
            return false;
        };
        rest
    } else {
        segment.arguments.clone()
    };
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    super::guard_diagnostics::approval_inspection(&words)
        && super::guard_diagnostics::safe_hol_guard_segment(executable, &arguments, cwd, 0)
}

/// Whether `command` is one plain read of Guard's own safety guide,
/// `cat ~/.hol-support/SAFETY.md` or the same file named by its absolute path
/// below `home_dir`, the hook's user home. The tilde form counts only
/// unquoted, where the shell expands it.
///
/// `hol-guard install codex` writes a managed block to the Codex `AGENTS.md`
/// asking the agent to read that guide before acting, and Codex does, as its
/// first shell call. The runtime uses this to keep a policy floor such as
/// `subprocess_action: review` from holding Guard's own instruction behind a
/// review. Only a single `cat` of that one regular file reaches here: no
/// other argument, flag, redirect, pipe, wrapper or environment assignment,
/// and no symbolic link at `.hol-support` or the guide itself.
pub fn guard_safety_guide_read_command(command: &str, home_dir: &str) -> bool {
    if command.contains(['<', '>', '|', ';', '&', '$', '`', '\\', '\n']) {
        return false;
    }
    let Ok(model) = crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }) else {
        return false;
    };
    if model.confidence != "exact"
        || model.uncertainty_reason.is_some()
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
    {
        return false;
    }
    let [segment] = model.segments.as_slice() else {
        return false;
    };
    let [target] = segment.arguments.as_slice() else {
        return false;
    };
    if segment.executable.as_deref() != Some("cat")
        || segment.tokens.len() != 2
        || segment.pipeline_index != 0
        || !segment.environment_names.is_empty()
        || !segment.wrapper_chain.is_empty()
        || segment.path_overridden
    {
        return false;
    }
    let home = std::path::Path::new(home_dir);
    if home_dir.is_empty() || !home.is_absolute() {
        return false;
    }
    let directory = home.join(".hol-support");
    let guide = directory.join("SAFETY.md");
    // The shell expands only an unquoted tilde; a quoted one names a
    // `~` directory below the working directory.
    let tilde = target == "~/.hol-support/SAFETY.md" && !command.contains(['\'', '"']);
    let named = tilde || std::path::Path::new(target.as_str()) == guide.as_path();
    named
        && std::fs::symlink_metadata(&directory)
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        && std::fs::symlink_metadata(&guide)
            .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}

#[cfg(test)]
#[path = "guard_home_option_tests.rs"]
mod tests;
