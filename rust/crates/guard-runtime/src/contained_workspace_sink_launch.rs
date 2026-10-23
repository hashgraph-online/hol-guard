//! One contained run: the sandboxed process, the Git bootstrap outside it,
//! and the private scratch both use.

use std::io::Write;
use std::os::unix::fs::DirBuilderExt;

use super::plan_check::Plan;
use super::*;

/// Everything one contained run needs besides its argv.
pub(super) struct Launch<'a> {
    pub(super) plan: &'a Plan,
    pub(super) workspace: &'a Path,
    pub(super) workspace_text: &'a str,
    pub(super) home: &'a str,
    pub(super) private: &'a PrivateRoot,
    pub(super) exec_roots: &'a [String],
    pub(super) write_denials: &'a [String],
    pub(super) signals: &'a process::Signals,
    /// Kept when the run failed on a blocked connection to this machine.
    pub(super) loopback: grant::LoopbackNote<'a>,
}

impl Launch<'_> {
    pub(super) fn contained(&self, argv: &[String]) -> Outcome<i32> {
        let private_root = path_text(&self.private.path)?;
        let mut source: Map<String, Value> = Map::new();
        for (name, value) in environment() {
            let value = match name.as_str() {
                "PYTHONPATH" => value
                    .split(':')
                    .map(|item| {
                        if item.is_empty() {
                            String::new()
                        } else {
                            py_normal(&expand_user(item))
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(":"),
                "VIRTUAL_ENV" => py_normal(&expand_user(&value)),
                _ => value,
            };
            source.insert(name, Value::String(value));
        }
        let launch_environment = native(
            "environment",
            json!({
                "source": source,
                "workspace": self.workspace_text,
                "cwd": self.workspace_text,
                "private_home": format!("{private_root}/home"),
                "private_tmp": format!("{private_root}/tmp"),
                "allowed_executables": [],
            }),
        )?;
        let mut environment: BTreeMap<String, String> = match launch_environment {
            Value::Object(entries) => entries
                .into_iter()
                .map(|(name, value)| match value {
                    Value::String(value) => Some((name, value)),
                    _ => None,
                })
                .collect::<Option<_>>(),
            _ => None,
        }
        .ok_or_else(|| {
            Failure::new(
                SANDBOX_UNAVAILABLE,
                "Invalid native restricted environment reply.",
            )
        })?;
        let empty_config = self.private.path.join("gitconfig");
        std::fs::write(&empty_config, b"").map_err(|_| {
            Failure::new(
                SANDBOX_UNAVAILABLE,
                "The workspace sandbox directory is unavailable.",
            )
        })?;
        link_private_caches(&format!("{private_root}/tmp"), self.exec_roots)?;
        environment.insert("PATH".into(), self.plan.sandbox_path.clone());
        environment.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
        environment.insert(
            "GIT_CONFIG_GLOBAL".into(),
            format!("{private_root}/gitconfig"),
        );
        environment.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
        if let Some(git) = trusted_git(self.workspace) {
            environment.extend(identity(self.workspace, &git, self.private));
        }
        let profile = native(
            "macos_profile",
            json!({
                "profile_version": self.plan.profile_version,
                "capabilities": self.plan.capabilities,
                "home": self.home,
                "workspace": self.workspace_text,
                "cwd": self.workspace_text,
                "private_root": private_root,
                "allowed_executables": [],
                "read_only_roots": self.plan.read_only_roots,
                "output_roots": [],
                "exec_roots": self.exec_roots,
                "write_denials": self.write_denials,
                "linked_git": self.plan.linked_git,
                "command": argv,
                "backend_executable": wire_path(Path::new(&self.plan.backend_executable)),
            }),
        )?;
        let Value::String(profile) = profile else {
            return Err(unavailable("invalid_reply"));
        };
        let mut backend = vec![
            self.plan.backend_executable.clone(),
            "-p".to_owned(),
            profile,
            "--".to_owned(),
        ];
        backend.extend(argv.iter().cloned());
        process::run_backend(
            &backend,
            &environment,
            self.workspace,
            &self.private.path,
            self.signals,
            RUN_TIMEOUT_SECONDS,
            &|| self.loopback.keep(),
        )
    }
}

/// Run `git init` outside the sandbox: it rewrites the write-denied
/// `.git/config`.
pub(super) fn bootstrap_init(
    arguments: &Value,
    workspace: &Path,
    private: &PrivateRoot,
) -> Outcome<()> {
    let arguments: Vec<String> = arguments
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .ok_or_else(|| Failure::invalid("Invalid workspace sandbox bootstrap."))?;
    let dot_git = workspace.join(".git");
    let git = trusted_git(workspace)
        .filter(|_| std::fs::symlink_metadata(&dot_git).is_err())
        .ok_or_else(|| Failure::new(SANDBOX_UNAVAILABLE, "Git initialization is unavailable."))?;
    let template = private.path.join("template");
    let home = private.path.join("init-home");
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(&template)
        .and_then(|()| builder.create(&home))
        .map_err(|_| Failure::new(SANDBOX_UNAVAILABLE, "Git initialization is unavailable."))?;
    let mut command = vec![
        git.to_string_lossy().into_owned(),
        "init".to_owned(),
        format!("--template={}", template.display()),
    ];
    command.extend(arguments);
    let environment = BTreeMap::from([
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        ("HOME".to_owned(), home.to_string_lossy().into_owned()),
        ("GIT_CONFIG_NOSYSTEM".to_owned(), "1".to_owned()),
        ("GIT_CONFIG_GLOBAL".to_owned(), "/dev/null".to_owned()),
        ("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned()),
    ]);
    let completed = process::run_captured(
        &command,
        &environment,
        workspace,
        &private.path,
        BOOTSTRAP_TIMEOUT,
    );
    let Some(completed) = completed else {
        return Err(Failure::with_exit(
            "pytest_restricted_git_init_failed",
            "git init failed.",
            1,
        ));
    };
    let _ = std::io::stdout().write_all(&completed.stdout);
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().write_all(&completed.stderr);
    let _ = std::io::stderr().flush();
    if completed.code != 0 {
        return Err(Failure::with_exit(
            "pytest_restricted_git_init_failed",
            "git init failed.",
            completed.code,
        ));
    }
    Ok(())
}

/// Author and committer from the host's global Git configuration.
fn identity(workspace: &Path, git: &Path, private: &PrivateRoot) -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    let home = crate::claude_hook_bridge::home_directory().unwrap_or_default();
    let environment = BTreeMap::from([
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        ("HOME".to_owned(), home.to_string_lossy().into_owned()),
        ("GIT_CONFIG_NOSYSTEM".to_owned(), "1".to_owned()),
    ]);
    for (key, part) in [("user.name", "NAME"), ("user.email", "EMAIL")] {
        let command = [
            git.to_string_lossy().into_owned(),
            "config".to_owned(),
            "--global".to_owned(),
            "--get".to_owned(),
            key.to_owned(),
        ];
        let Some(completed) = process::run_captured(
            &command,
            &environment,
            workspace,
            &private.path,
            IDENTITY_TIMEOUT,
        ) else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(&completed.stdout) else {
            continue;
        };
        let value = crate::guard_store_json::py_strip(text);
        if completed.code == 0 && !value.is_empty() && !value.contains(['\n', '\0']) {
            found.insert(format!("GIT_AUTHOR_{part}"), value.to_owned());
            found.insert(format!("GIT_COMMITTER_{part}"), value.to_owned());
        }
    }
    found
}

/// The Git a host command in `cwd` would run, when it is a trusted binary.
fn trusted_git(cwd: &Path) -> Option<PathBuf> {
    let snapshot: BTreeMap<String, String> = environment()
        .into_iter()
        .filter(|(name, _)| name.starts_with("GIT_") || GIT_SNAPSHOT_NAMES.contains(&name.as_str()))
        .collect();
    let home = crate::claude_hook_bridge::home_directory()?;
    let groups = crate::edge_git_push::groups()?;
    crate::git_execution_safety_binary::resolve_trusted_git(cwd, &snapshot, &home, &groups)
}

/// Owner-only scratch for one contained run, removed when dropped.
pub(super) struct PrivateRoot {
    pub(super) path: PathBuf,
}

impl PrivateRoot {
    pub(super) fn create() -> Option<Self> {
        let template = std::env::temp_dir().join("hol-guard-workspace-XXXXXX");
        let created = nix::unistd::mkdtemp(&template).ok()?;
        let Ok(path) = std::fs::canonicalize(&created) else {
            let _ = std::fs::remove_dir(&created);
            return None;
        };
        // One owner only: its drop removes the directory.
        let root = Self { path };
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(root.path.join("home")).ok()?;
        builder.create(root.path.join("tmp")).ok()?;
        if let Some(home) = crate::claude_hook_bridge::home_directory() {
            seed_safety_guide(&home, &root.path.join("home"));
        }
        Some(root)
    }
}

/// The largest safety guide copied into the private home.
const MAX_SAFETY_GUIDE_BYTES: u64 = 64 * 1024;

/// Link the host caches a contained run reads into the tree it owns.
///
/// Cargo takes its locks inside `CARGO_HOME`, so a contained run needs one it
/// can write; the fetched crate sources it only reads stay where the host
/// keeps them, linked in under the names cargo looks for. A link may name an
/// entry below a cache rather than the cache itself, which leaves the
/// directory holding it one the run owns and can add to. Nothing is linked
/// when the native side grants no cache, and the plan's own executable roots
/// decide that: a run the plan gave no cache to is not handed a link naming
/// one either.
fn link_private_caches(private_tmp: &str, exec_roots: &[String]) -> Outcome<()> {
    let Value::Array(links) = native(
        "private_links",
        json!({ "private_tmp": private_tmp, "roots": exec_roots }),
    )?
    else {
        return Err(unavailable("invalid_reply"));
    };
    for entry in links {
        let (Some(Value::String(link)), Some(Value::String(target))) =
            (entry.get("link"), entry.get("target"))
        else {
            return Err(unavailable("invalid_reply"));
        };
        let link = Path::new(link);
        if let Some(parent) = link.parent() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(parent)
                .map_err(|_| {
                    Failure::new(
                        SANDBOX_UNAVAILABLE,
                        "The workspace sandbox directory is unavailable.",
                    )
                })?;
        }
        let _ = std::os::unix::fs::symlink(target, link);
    }
    Ok(())
}

/// Copy Guard's safety guide into the private home, so the
/// `~/.hol-support/SAFETY.md` that classification admits reads the same text
/// inside the sandbox. `.hol-support` and the guide are opened relative to
/// descriptors without following links, and only a regular file with one link
/// is copied: a link or directory swapped in at either step would otherwise
/// put another file in reach of the sandboxed command. A guide that cannot be
/// copied is left out and the read fails in the sandbox.
pub(super) fn seed_safety_guide(home: &Path, private_home: &Path) {
    use nix::fcntl::{open, openat, OFlag};
    use nix::sys::stat::Mode;
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let directory_flags =
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let Ok(home) = open(
        home,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) else {
        return;
    };
    let Ok(directory) = openat(&home, ".hol-support", directory_flags, Mode::empty()) else {
        return;
    };
    let file_flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
    let Ok(file) = openat(&directory, "SAFETY.md", file_flags, Mode::empty()) else {
        return;
    };
    let mut file = std::fs::File::from(file);
    let Ok(metadata) = file.metadata() else {
        return;
    };
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.len() > MAX_SAFETY_GUIDE_BYTES
    {
        return;
    }
    let mut text = Vec::new();
    if (&mut file)
        .take(MAX_SAFETY_GUIDE_BYTES + 1)
        .read_to_end(&mut text)
        .is_err()
        || text.len() as u64 > MAX_SAFETY_GUIDE_BYTES
    {
        return;
    }
    let target = private_home.join(".hol-support");
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    if builder.create(&target).is_err() {
        return;
    }
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(target.join("SAFETY.md"))
        .and_then(|mut copy| copy.write_all(&text));
    if written.is_err() {
        let _ = std::fs::remove_file(target.join("SAFETY.md"));
    }
}

impl Drop for PrivateRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
