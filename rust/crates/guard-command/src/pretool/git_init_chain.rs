//! A scratch repository made and used in one chain:
//! `git init -q /tmp/x/scratch && cd /tmp/x/scratch && echo hi > a.txt &&
//! git add a.txt && git -c user.name=t -c user.email=t@t commit -qm test`.
//!
//! The first step is the `git init` `git_init_target` proves: a directory
//! that does not exist yet, below a temporary directory only the user can
//! write, with no template directory and no conditional include that could
//! configure the new repository. Every step runs only after the one before it
//! succeeded, so the rest runs in that new, empty repository or not at all:
//!
//! * the second step is `cd` to the same target;
//! * every later step prints (`echo`, `printf`, whose output a redirect may
//!   save to a new, non-hidden file there), stages files with `git add`, or
//!   makes an unsigned `git commit -m`, with `-c` naming only the commit
//!   identity;
//! * the target's parent is a temporary directory only the user can write,
//!   so no one else can add a hook to the new repository before it runs;
//! * the new repository's hooks are Git's own samples, so an inherited
//!   `core.hooksPath` must name a directory only the user can write with no
//!   executable hook in it, and the configuration must start no filter,
//!   fsmonitor, signing or hook program, as for the other local Git writes.
//!
//! Nothing outside the new directory changes. A target that already exists,
//! another step, another `-c` setting or a hidden file keeps the review.

use crate::{CanonicalCommandV1, CommandSegmentV1};
use guard_contracts::{GuardExecutionEnvironmentV1, PreToolResultV1};
use std::fs;
use std::path::{Component, Path};
use std::time::Instant;

pub(crate) const REASON: &str = "native_exact_safe_git_init_chain";

/// The declarative review rules the chain's Git steps may raise.
const RULES: &[&str] = &["command.git.add", "command.git.commit"];

/// The Git steps of a chain with the shape above, by index, or `None`.
fn shape(model: &CanonicalCommandV1) -> Option<Vec<usize>> {
    let [init, cd, rest @ ..] = model.segments.as_slice() else {
        return None;
    };
    if model.confidence != "exact"
        || model.uncertainty_reason.is_some()
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || rest.is_empty()
        || init.executable.as_deref() != Some("git")
        || init.arguments.first().map(String::as_str) != Some("init")
        || cd.executable.as_deref() != Some("cd")
        || cd.arguments.as_slice() != [super::git_init_target::target(&init.arguments[1..])?]
    {
        return None;
    }
    let plain = |segment: &CommandSegmentV1| {
        segment.wrapper_chain.is_empty()
            && segment.environment_names.is_empty()
            && !segment.path_overridden
            && segment.pipeline_index == 0
            && !segment.text.contains(['$', '`', '\n', '\r'])
            // A quoted `<` or `>` (`--author="A <a@example.test>"`) is data.
            && !crate::codex_output_search::has_unquoted_shell_control(&segment.text)
    };
    let and_chained = (1..model.segments.len()).all(|index| {
        super::worktree_add::separator_between(model, index - 1, index)
            .is_some_and(|separator| separator.trim() == "&&")
    });
    if !and_chained || !model.segments.iter().all(plain) {
        return None;
    }
    let mut git = vec![0];
    for (index, segment) in model.segments.iter().enumerate().skip(2) {
        match segment.executable.as_deref() {
            Some("echo" | "printf") => {}
            Some("git") if git_step(&segment.arguments) => git.push(index),
            _ => return None,
        }
    }
    Some(git)
}

/// `git add` or `git commit -m`, after `-c` pairs that set only the commit
/// identity; any other setting could name a program.
fn git_step(arguments: &[String]) -> bool {
    let mut words: &[String] = arguments;
    while let [flag, setting, rest @ ..] = words {
        if flag != "-c" {
            break;
        }
        let key = setting
            .split_once('=')
            .map(|(key, _)| key.to_ascii_lowercase());
        if !matches!(key.as_deref(), Some("user.name" | "user.email")) {
            return false;
        }
        words = rest;
    }
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    super::git_local_writes::index_or_commit(&words)
}

/// Whether the redirect projection may take a chain of this shape that
/// writes `targets`: each is one plain name, which lands in the new
/// directory, or, written before the `cd`, in the working directory the
/// projection's own target check already proved.
pub(in crate::pretool) fn admits(model: &CanonicalCommandV1, targets: &[String]) -> bool {
    shape(model).is_some()
        && targets.iter().all(|target| {
            !target.is_empty() && !target.starts_with('.') && !target.contains(['/', '\\', ':'])
        })
}

/// Whether the chain has the shape above, its target is fresh and the
/// session's configuration lets the new repository start no program.
fn proven(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> Option<Vec<usize>> {
    let git = shape(model)?;
    // Directly in the shared temporary root, another user could create the
    // directory first and plant a hook there before the commit runs.
    let target = Path::new(super::git_init_target::target(
        &model.segments[0].arguments[1..],
    )?);
    // `cd` searches CDPATH for a relative operand that does not start with a
    // `.` or `..` component, and could enter some other repository.
    let first = target.components().next();
    if !target.is_absolute()
        && !matches!(first, Some(Component::CurDir | Component::ParentDir))
        && !context.cdpath_unset
    {
        return None;
    }
    let parent = Path::new(context.cwd?).join(target).parent()?.to_path_buf();
    if !super::git_routes::private_temporary_parent(&fs::canonicalize(parent).ok()?, context) {
        return None;
    }
    let (effective, repository) = super::git_init_target::fresh(
        &model.segments[0],
        context,
        deadline,
        execution_environment,
    )?;
    let hooks_inert = effective
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("core.hookspath"))
        // Git expands `~/` from the shell's HOME, so it must be the home checked.
        .all(|(_, values)| {
            hooks_path_inert(
                values,
                context.home_dir.filter(|_| context.shell_home_matches),
            )
        });
    (hooks_inert
        && super::git_local_writes::inert(&effective, &repository)
        && !super::git_local_writes::signs_by_default(&effective))
    .then_some(git)
}

/// Whether an inherited `core.hooksPath` (a developer's global
/// `~/.config/git/hooks`) can run nothing for this chain: each value is
/// absolute or below home, and names a directory that only the user can
/// write and that holds no executable file or link, or a missing one whose
/// nearest existing ancestor only the user can write. A relative or
/// shared location (`/tmp/hooks`) keeps the review.
fn hooks_path_inert(values: &[String], home: Option<&str>) -> bool {
    values.iter().all(|value| {
        let path = match value.strip_prefix("~/") {
            Some(rest) => match home {
                Some(home) if Path::new(home).is_absolute() => Path::new(home).join(rest),
                _ => return false,
            },
            None if Path::new(value).is_absolute() && !value.contains("..") => {
                Path::new(value).to_path_buf()
            }
            None => return false,
        };
        hook_directory_inert(&path)
    })
}

#[cfg(unix)]
fn hook_directory_inert(path: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let me = nix::unistd::geteuid().as_raw();
    let private = |path: &Path| {
        fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.is_dir() && metadata.uid() == me && metadata.mode() & 0o022 == 0
        })
    };
    // Every higher ancestor belongs to the user or root and stays closed to
    // other writers unless sticky, so nobody can rename the checked tree away.
    let steady = |path: &Path| {
        fs::symlink_metadata(path).is_ok_and(|metadata| {
            (metadata.uid() == me || metadata.uid() == 0)
                && (metadata.mode() & 0o022 == 0 || metadata.mode() & 0o1000 != 0)
        })
    };
    let mut existing = path;
    while fs::symlink_metadata(existing).is_err() {
        let Some(parent) = existing.parent() else {
            return false;
        };
        existing = parent;
    }
    if !existing.ancestors().skip(1).all(steady) {
        return false;
    }
    if existing != path {
        return private(existing);
    }
    let Ok(entries) = fs::read_dir(path) else {
        return false;
    };
    private(path)
        && path.parent().is_some_and(private)
        && entries.take(257).enumerate().all(|(index, entry)| {
            index < 256
                && entry
                    .and_then(|entry| entry.metadata())
                    .is_ok_and(|metadata| {
                        let executable =
                            metadata.is_file() && metadata.permissions().mode() & 0o111 != 0;
                        !metadata.file_type().is_symlink() && !executable
                    })
        })
}

#[cfg(not(unix))]
fn hook_directory_inert(_path: &Path) -> bool {
    false
}

/// Turn the generic review of a proven chain into an allow when the only
/// extension rules it matched are the Git steps' own. The caller has checked
/// that the result is that review of a command with no sensitive target.
pub(in crate::pretool) fn settle(
    result: &mut PreToolResultV1,
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) {
    let Some(git) = proven(model, context, deadline, execution_environment) else {
        return;
    };
    let explained = result.command_extensions.as_ref().is_none_or(|extensions| {
        extensions.binding.uncertainty_count == 0
            && extensions.evaluation_error.is_none()
            && extensions.permission_observations.is_empty()
            && extensions.observations.iter().all(|observation| {
                observation.uncertainty_reasons.is_empty()
                    && RULES.contains(&observation.rule_id.as_str())
                    && observation
                        .matcher_evidence
                        .iter()
                        .map(|evidence| evidence.segment_index)
                        .chain(observation.effective_segment_indexes.iter().copied())
                        .all(|index| git.contains(&index))
            })
    });
    if !explained {
        return;
    }
    result.minimum_action = "allow".into();
    result.policy_action = "allow".into();
    result.decision = "allow".into();
    result.explicitly_benign = true;
    result.reason_code = REASON.into();
    result.reason = concat!(
        "The Rust command authority proved this chain creates a new repository in a fresh ",
        "directory under the user's own temporary directory and only writes, stages and ",
        "commits files there, starting no configured program or hook.",
    )
    .into();
}

#[cfg(test)]
mod tests {
    use super::{admits, shape};

    fn model(command: &str) -> Option<crate::CanonicalCommandV1> {
        crate::parse_command(&crate::CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "pre-tool-generic".to_owned(),
        })
        .ok()
    }

    fn shaped(command: &str) -> Option<Vec<usize>> {
        shape(&model(command)?)
    }

    #[test]
    fn only_prints_stages_and_identity_commits_follow_the_cd() {
        let base = "git init -q /tmp/o/s && cd /tmp/o/s";
        for (rest, git) in [
            (
                "echo hi && git add a.txt && git -c user.name=t -c user.email=t@t commit -qm test",
                vec![0, 3, 4],
            ),
            (
                "printf 'x\\n' && git add -A && git commit -m init",
                vec![0, 3, 4],
            ),
            (
                "git add . && git commit --author='A <a@example.test>' -m x",
                vec![0, 2, 3],
            ),
        ] {
            assert_eq!(shaped(&format!("{base} && {rest}")), Some(git), "{rest}");
        }
        for command in [
            "git init -q /tmp/o/s && cd /tmp/o/t && git add .",
            "git init -q /tmp/o/s; cd /tmp/o/s && git add .",
            "git init -q /tmp/o/s && cd /tmp/o/s && git add . || true",
            "git init -q /tmp/o/s && cd /tmp/o/s",
            "git init -q /tmp/o/s && cd /tmp/o/s && git -c core.hooksPath=h commit -m x",
            "git init -q /tmp/o/s && cd /tmp/o/s && git -c user.name commit -m x",
            "git init -q /tmp/o/s && cd /tmp/o/s && git commit -S -m x",
            "git init -q /tmp/o/s && cd /tmp/o/s && git commit",
            "git init -q /tmp/o/s && cd /tmp/o/s && git add -f a.txt",
            "git init -q /tmp/o/s && cd /tmp/o/s && git config core.hooksPath h",
            "git init -q /tmp/o/s && cd /tmp/o/s && ln -s ~/.ssh k && git add k",
            "git init -q /tmp/o/s && cd /tmp/o/s && echo $(id) && git add .",
            "git init --bare /tmp/o/s && cd /tmp/o/s && git add .",
            "cd /tmp/o/s && git init -q /tmp/o/s && git add .",
        ] {
            assert_eq!(shaped(command), None, "{command}");
        }
        let chain = model(&format!("{base} && echo hi && git add a.txt")).unwrap();
        assert!(admits(&chain, &["a.txt".to_owned()]));
        for target in [".gitattributes", "sub/a.txt", "/tmp/o/a.txt", ""] {
            assert!(!admits(&chain, &[target.to_owned()]), "{target}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn hooks_below_an_ancestor_others_can_rename_keep_the_review() {
        use std::os::unix::fs::PermissionsExt;
        let open = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/hook-ancestors")
            .join(std::process::id().to_string());
        let hooks = open.join("home/hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        for path in [&hooks, &open.join("home"), &open] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        // The checkout's own ancestors decide the baseline; only the open
        // directory changes below.
        let baseline = super::hook_directory_inert(&hooks);
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!super::hook_directory_inert(&hooks));
        assert!(!super::hook_directory_inert(&hooks.join("missing")));
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert_eq!(super::hook_directory_inert(&hooks), baseline);
        std::fs::remove_dir_all(&open).unwrap();
    }
}
