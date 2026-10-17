//! `git push [-u] origin <current-branch|HEAD>` proven without review.
//!
//! The command shape is proven here; whether the repository may push is a
//! question about the machine: which Git runs, which remote it names, which
//! credential helper answers and which hooks fire. The resident runtime answers
//! that with the same checks the compound Git decision uses and registers the
//! answer through [`install_git_push_verdict`]. Without a registered verdict the
//! push keeps its review.
use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;

/// What the runtime verdict inspects before a push proceeds.
pub struct GitPushRequest<'a> {
    /// The trusted Git binary the shell resolves.
    pub git: &'a Path,
    /// The canonical repository directory the push runs in.
    pub repository: &'a Path,
    /// The branch named on the command line.
    pub branch: &'a str,
    /// The `HOME` the agent's shell runs with.
    pub home: &'a Path,
    /// The `PATH` the agent's shell runs with.
    pub path: &'a str,
    /// The `XDG_CONFIG_HOME` the agent's shell runs with, when set.
    pub xdg_config_home: Option<&'a str>,
    /// The same command first creates `branch` at the checked-out commit and
    /// switches to it, so `branch` must not exist yet and the branch checked
    /// out now is the one it starts from.
    pub creates_branch: bool,
}

/// Answers whether the push may run: the branch is the checked-out branch,
/// origin is a credential-free GitHub HTTPS remote, every credential helper and
/// hook is trusted, and no configuration routes the push elsewhere.
pub type GitPushVerdict = fn(&GitPushRequest<'_>) -> bool;

static VERDICT: OnceLock<GitPushVerdict> = OnceLock::new();

/// Registers the runtime verdict. The first registration wins.
pub fn install_git_push_verdict(verdict: GitPushVerdict) {
    let _ = VERDICT.set(verdict);
}

/// Variables that change how Git authenticates, which transport it uses or how
/// it verifies the server. The verdict's probes never see the agent's own
/// environment, so any of these keeps the push under review.
const TRANSPORT_ENVIRONMENT: &[&str] = &[
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_PROXY_COMMAND",
    "GIT_EXEC_PATH",
    "GIT_ALLOW_PROTOCOL",
    "GIT_PROTOCOL_FROM_USER",
];
const TRANSPORT_PREFIXES: &[&str] = &["GIT_SSL_", "GIT_SSH", "GIT_HTTP", "GIT_CURL", "SSL_CERT_"];
/// Certificate anchors, usually for a company's TLS-inspecting proxy that
/// already sees all of the user's traffic. They choose which authority signs
/// for the server but leave origin, credentials and verification where they
/// were. The hook stamps them from the session, which the agent's command
/// cannot set; an inline assignment on the command is still refused.
pub(super) const CERTIFICATE_ANCHORS: &[&str] = &[
    "GIT_SSL_CAINFO",
    "GIT_SSL_CAPATH",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
];

/// Whether an exported variable changes how Git authenticates, which
/// transport it uses or how it verifies the server.
fn routes_transport(name: &str) -> bool {
    let key = name.to_ascii_uppercase();
    !CERTIFICATE_ANCHORS.contains(&key.as_str())
        && (TRANSPORT_ENVIRONMENT.contains(&key.as_str())
            || TRANSPORT_PREFIXES
                .iter()
                .any(|prefix| key.starts_with(prefix)))
}

/// The trusted Git a `git push` from `cwd` would run, after the same
/// environment checks the native push proof makes, or `None` when the agent's
/// environment could reroute, re-authenticate or inject code into the push.
/// A one-time approval of a reviewed push binds to the same answer.
pub fn push_environment_git(
    execution_environment: &guard_contracts::GuardExecutionEnvironmentV1,
    home: &Path,
    cwd: &Path,
) -> Option<std::path::PathBuf> {
    let (home, cwd) = (
        std::fs::canonicalize(home).ok()?,
        std::fs::canonicalize(cwd).ok()?,
    );
    let clean = super::git_config::clean_environment(Some(execution_environment), &home, &cwd)
        && !execution_environment
            .environment_names
            .iter()
            .any(|name| routes_transport(name))
        && execution_environment
            .xdg_config_home
            .as_deref()
            .is_none_or(|xdg| Path::new(xdg).is_absolute());
    if !clean {
        return None;
    }
    super::git_config::trusted_command("git", &home, &cwd, Some(execution_environment))
}

struct Push<'a> {
    directory: Option<&'a str>,
    branch: &'a str,
}

pub(super) fn exact_safe_command(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(verdict) = VERDICT.get() else {
        return false;
    };
    if model.confidence != "exact"
        || model.path_overridden
        || model.segments.is_empty()
        || !model.wrapper_chain.is_empty()
    {
        return false;
    }
    let cwd_proof = model
        .segments
        .iter()
        .position(|segment| segment.executable.as_deref() == Some("cd"))
        .and_then(|cd_index| {
            super::worktree_add::verified_worktree_cwd_context(model, cd_index, context)
        });
    let proof_context = super::PathContext {
        cwd: cwd_proof
            .as_ref()
            .map(|proof| proof.cwd.as_str())
            .or(context.cwd),
        ..context
    };
    let mut push_seen = false;
    for (index, segment) in model.segments.iter().enumerate() {
        if segment.executable.as_deref() == Some("cd") {
            if cwd_proof
                .as_ref()
                .is_none_or(|proof| proof.cd_index != index)
            {
                return false;
            }
            continue;
        }
        let executable = segment
            .executable
            .as_deref()
            .map(super::executable_basename);
        if executable == Some("git") && parse(segment).is_some() {
            if push_seen
                || segment.pipeline_index != 0
                || deadline.is_some_and(|deadline| Instant::now() >= deadline)
                || !proven_push(
                    segment,
                    proof_context,
                    execution_environment,
                    *verdict,
                    None,
                )
            {
                return false;
            }
            push_seen = true;
            continue;
        }
        if segment.pipeline_index > 0 {
            let Some(name @ ("tail" | "head")) = executable else {
                return false;
            };
            if !super::safe_reads::safe_head_tail_stdin_arguments(&segment.arguments)
                || !trusted_filter(name, proof_context, execution_environment)
            {
                return false;
            }
        }
        if !super::segment_proof::exact_safe_segment_with_context(
            model,
            segment,
            false,
            proof_context,
        ) {
            return false;
        }
    }
    push_seen
}

/// Whether `segment` is `git push [-u] origin <branch>` from the shell's own
/// directory, the only push a chain of local Git writes may end with.
pub(super) fn chained(segment: &CommandSegmentV1) -> bool {
    plain_git(segment) && parse(segment).is_some_and(|push| push.directory.is_none())
}

/// Git itself, named first: the push proof resolves and runs this program, so
/// any other executable, a wrapper such as `env -C` or an overridden path is
/// refused.
fn plain_git(segment: &CommandSegmentV1) -> bool {
    let first = segment.text.split_whitespace().next();
    [
        segment.executable.as_deref(),
        segment.tokens.first().map(String::as_str),
        first,
    ]
    .into_iter()
    .all(|word| word.map(super::executable_basename) == Some("git"))
        && !segment.path_overridden
        && segment.wrapper_chain.is_empty()
}

/// Proves a push that follows proven local Git writes in one chain, with the
/// same runtime verdict a push alone gets. `created` is the branch an earlier
/// `git switch -c` or `git checkout -b` in the chain creates and checks out.
pub(super) fn chained_push_proven(
    segment: &CommandSegmentV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    created: Option<&str>,
) -> bool {
    let Some(verdict) = VERDICT.get() else {
        return false;
    };
    chained(segment)
        && segment.pipeline_index == 0
        && deadline.is_none_or(|deadline| Instant::now() < deadline)
        && proven_push(segment, context, execution_environment, *verdict, created)
}

fn trusted_filter(
    name: &str,
    context: super::PathContext<'_>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let (Some(home), Some(cwd)) = (context.home_dir, context.cwd) else {
        return false;
    };
    let (Ok(home), Ok(cwd)) = (std::fs::canonicalize(home), std::fs::canonicalize(cwd)) else {
        return false;
    };
    execution_environment.is_some()
        && super::git_config::trusted_command(name, &home, &cwd, execution_environment).is_some()
}

fn proven_push(
    segment: &CommandSegmentV1,
    context: super::PathContext<'_>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    verdict: GitPushVerdict,
    created: Option<&str>,
) -> bool {
    let Some(environment) = execution_environment else {
        return false;
    };
    if !plain_git(segment) {
        return false;
    }
    let Some(spec) = parse(segment) else {
        return false;
    };
    // `HEAD` after the command's own `git switch -c` names the new branch.
    let branch = match created {
        None => spec.branch,
        Some(name) if spec.branch == name || spec.branch == "HEAD" => name,
        Some(_) => return false,
    };
    let (Some(declared_home), Some(declared_cwd)) = (context.home_dir, context.cwd) else {
        return false;
    };
    let (Ok(home), Ok(cwd)) = (
        std::fs::canonicalize(declared_home),
        std::fs::canonicalize(declared_cwd),
    ) else {
        return false;
    };
    let Some(shell_home) = environment.home.as_deref().map(Path::new) else {
        return false;
    };
    if !segment.environment_names.is_empty()
        || !super::git_config::clean_environment(execution_environment, &home, &cwd)
        || environment
            .environment_names
            .iter()
            .any(|name| routes_transport(name))
    {
        return false;
    }
    // `git -C '~/x'` receives a literal relative `~/x`; only an unquoted `~`
    // reaches Git as the home directory the proof checks.
    if !super::directory_targets::home_targets_unquoted(segment)
        || environment
            .xdg_config_home
            .as_deref()
            .is_some_and(|xdg| !Path::new(xdg).is_absolute())
    {
        return false;
    }
    let Some(repository) = repository(spec.directory, &home, &cwd, shell_home) else {
        return false;
    };
    let Some(git) = super::git_config::trusted_command(
        segment.executable.as_deref().unwrap_or("git"),
        &home,
        &cwd,
        execution_environment,
    ) else {
        return false;
    };
    verdict(&GitPushRequest {
        git: &git,
        repository: &repository,
        branch,
        home: shell_home,
        path: &environment.path,
        xdg_config_home: environment.xdg_config_home.as_deref(),
        creates_branch: created.is_some(),
    })
}

/// The directory the push runs in: the shell's cwd or its `-C` target, which
/// must be an existing directory under the declared home.
fn repository(
    directory: Option<&str>,
    home: &Path,
    cwd: &Path,
    shell_home: &Path,
) -> Option<PathBuf> {
    let target = match directory {
        None => cwd.to_path_buf(),
        Some(value) => {
            if !super::safe_directory_target(value) || super::sensitive_read_path_argument(value) {
                return None;
            }
            match value.strip_prefix('~') {
                // The shell expands `~` from its own HOME.
                Some(rest) if rest.is_empty() || rest.starts_with('/') => {
                    if std::fs::canonicalize(shell_home).ok().as_deref() != Some(home) {
                        return None;
                    }
                    home.join(rest.trim_start_matches('/'))
                }
                Some(_) => return None,
                None => cwd.join(value),
            }
        }
    };
    let repository = std::fs::canonicalize(target).ok()?;
    (repository.is_dir() && repository.starts_with(home)).then_some(repository)
}

fn parse(segment: &CommandSegmentV1) -> Option<Push<'_>> {
    let arguments = match segment.arguments.split_last() {
        Some((last, rest)) if last == "2>&1" => rest,
        _ => &segment.arguments[..],
    };
    let (directory, rest) = match arguments {
        [flag, directory, rest @ ..] if flag == "-C" => (Some(directory.as_str()), rest),
        _ => (None, arguments),
    };
    let (subcommand, rest) = rest.split_first()?;
    if subcommand != "push" {
        return None;
    }
    let mut operands = Vec::new();
    for argument in rest {
        match argument.as_str() {
            "-u" | "--set-upstream" | "-q" | "--quiet" => {}
            value if value.starts_with('-') => return None,
            value => operands.push(value),
        }
    }
    match operands[..] {
        ["origin", branch] if super::worktree_add::valid_branch_name(branch) => {
            Some(Push { directory, branch })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::parse;

    fn shape(command: &str) -> Option<(Option<String>, String)> {
        let model = crate::parse_command(&crate::CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .ok()?;
        let segment = model.segments.first()?;
        parse(segment).map(|push| (push.directory.map(str::to_owned), push.branch.to_owned()))
    }

    #[test]
    fn named_branch_pushes_to_origin_are_recognized() {
        for (command, directory, branch) in [
            ("git push -u origin feature/one", None, "feature/one"),
            ("git push --set-upstream origin fix-two", None, "fix-two"),
            ("git push origin main", None, "main"),
            ("git push -u origin HEAD", None, "HEAD"),
            ("git push -q -u origin topic 2>&1", None, "topic"),
            (
                "git -C ../sibling push -u origin topic",
                Some("../sibling"),
                "topic",
            ),
        ] {
            assert_eq!(
                shape(command),
                Some((directory.map(str::to_owned), branch.to_owned())),
                "{command}"
            );
        }
    }

    #[test]
    fn other_push_forms_are_not_recognized() {
        for command in [
            "git push",
            "git push origin",
            "git push --force origin main",
            "git push -f origin main",
            "git push --force-with-lease origin main",
            "git push --mirror origin",
            "git push --all origin",
            "git push --tags origin",
            "git push --delete origin main",
            "git push origin :main",
            "git push origin +main",
            "git push origin HEAD:refs/heads/main",
            "git push origin main other",
            "git push upstream main",
            "git push https://github.com/example/repo.git main",
            "git push --receive-pack=/tmp/x origin main",
            "git push --repo=elsewhere origin main",
            "git push -o ci.skip origin main",
            "git push origin main..other",
            "git push origin -main",
            "git -c core.sshCommand=x push origin main",
            "git --git-dir=/tmp/x push origin main",
            "git push origin main > out.txt",
        ] {
            assert_eq!(shape(command), None, "{command}");
        }
    }
}
