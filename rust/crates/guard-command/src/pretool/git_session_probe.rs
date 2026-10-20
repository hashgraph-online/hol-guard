//! Execution-free Git probes for session operations: a remote refresh and
//! worktree maintenance. The probe sees the
//! configuration the agent's own Git would see (home, XDG directory, system
//! file switch and `-C` routes) and only runs Git built-ins that never start
//! a configured helper.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::Instant;

#[path = "apple_developer_tools.rs"]
pub(super) mod apple_developer_tools;

/// Matches the runtime probe's output bound. Long-lived repositories collect
/// large `branch.*` sections, and a smaller cap here turned an ordinary fetch
/// into a review that the runtime itself would have verified.
const CONFIG_LIMIT: u64 = 8 * 1024 * 1024;
const TEXT_LIMIT: u64 = 4096;

/// Session variables Git reads for its own behavior that cannot change where
/// a remote operation connects, how it authenticates or what it runs. The
/// session's certificate anchors (`GIT_SSL_CAINFO`, `GIT_SSL_CAPATH`) are
/// accepted as well, as they are for a push: they pick which authority signs
/// for the server, usually a company's TLS-inspecting proxy, and run nothing.
const INERT_GIT_VARIABLES: &[&str] = &[
    "GIT_CONFIG_NOSYSTEM",
    "GIT_EDITOR",
    "GIT_OPTIONAL_LOCKS",
    "GIT_PAGER",
    "GIT_TERMINAL_PROMPT",
];

pub(super) struct Probe {
    base: Command,
    leading: Vec<String>,
    deadline: Instant,
    pub(super) home: PathBuf,
    pub(super) cwd: PathBuf,
    environment: guard_contracts::GuardExecutionEnvironmentV1,
}

impl Probe {
    pub(super) fn new(
        executable: &str,
        leading: &[String],
        context: super::PathContext<'_>,
        deadline: Option<Instant>,
        execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    ) -> Option<Self> {
        let probe_deadline = Instant::now() + super::git_probe::PROBE_BUDGET;
        let deadline = deadline.unwrap_or(probe_deadline).min(probe_deadline);
        let environment = execution_environment?;
        let declared_home = Path::new(context.home_dir?);
        let declared_cwd = Path::new(context.cwd?);
        if Instant::now() >= deadline
            || !declared_home.is_absolute()
            || !declared_cwd.is_absolute()
            || leading.iter().any(|argument| argument.starts_with('~'))
        {
            return None;
        }
        let home = fs::canonicalize(declared_home).ok()?;
        let cwd = fs::canonicalize(declared_cwd).ok()?;
        if !home.is_dir()
            || !cwd.is_dir()
            || !super::git_config::clean_environment(Some(environment), &home, &cwd)
            || environment.environment_names.iter().any(|name| {
                let key = name.to_ascii_uppercase();
                (key.starts_with("GIT_")
                    && !INERT_GIT_VARIABLES.contains(&key.as_str())
                    && !super::git_push::CERTIFICATE_ANCHORS.contains(&key.as_str()))
                    || key == "SSH_ASKPASS"
            })
        {
            return None;
        }
        let git_home = Path::new(environment.home.as_deref()?);
        if !git_home.is_absolute() || fs::canonicalize(git_home).ok()? != home {
            return None;
        }
        let binary =
            super::git_config::trusted_command(executable, &home, &cwd, Some(environment))?;
        let mut base = Command::new(binary);
        base.env_clear();
        #[cfg(windows)]
        for key in ["SYSTEMROOT", "WINDIR"] {
            if let Some(value) = std::env::var_os(key) {
                base.env(key, value);
            }
        }
        if let Some(directory) = environment.xdg_config_home.as_deref() {
            base.env("XDG_CONFIG_HOME", directory);
        }
        if environment.git_config_no_system {
            base.env("GIT_CONFIG_NOSYSTEM", "1");
        }
        base.current_dir(declared_cwd)
            .env("HOME", git_home)
            .env("USERPROFILE", git_home);
        Some(Self {
            base,
            leading: leading.to_vec(),
            deadline,
            home,
            cwd,
            environment: environment.clone(),
        })
    }

    fn run(&self, routed: bool, arguments: &[&str], limit: u64) -> Option<(ExitStatus, Vec<u8>)> {
        let mut command = super::git_probe::copy_command(&self.base)?;
        if routed {
            command.args(&self.leading);
        }
        command.args(arguments);
        super::git_probe::output(&mut command, self.deadline, limit)
    }

    /// The single line a successful query prints, or `None`.
    pub(super) fn text(&self, arguments: &[&str]) -> Option<String> {
        let (status, output) = self.run(true, arguments, TEXT_LIMIT)?;
        status.success().then_some(())?;
        line(&output)
    }

    /// Everything a successful query prints, or `None`.
    pub(super) fn output(&self, arguments: &[&str]) -> Option<Vec<u8>> {
        let (status, output) = self.run(true, arguments, CONFIG_LIMIT)?;
        status.success().then_some(output)
    }

    /// Effective and repository-scoped configuration, includes followed.
    pub(super) fn config(
        &self,
    ) -> Option<(
        super::git_remote_config::GitConfig,
        super::git_remote_config::GitConfig,
    )> {
        let (status, output) = self.run(
            true,
            &[
                "--no-pager",
                "config",
                "--includes",
                "--show-scope",
                "--null",
                "--list",
            ],
            CONFIG_LIMIT,
        )?;
        if !(status.success() || status.code() == Some(1) && output.is_empty()) {
            return None;
        }
        super::git_remote_config::parse_scoped(&output)
    }

    /// No named hook can run: each is absent, a non-executable file or a
    /// known script that does nothing here (see `git_hook_files`). A hook
    /// manager's shim is not one: the project hook it forwards to is read from
    /// the working tree, which the writes this answers for may change.
    pub(super) fn hooks_inert<'a>(&self, names: impl IntoIterator<Item = &'a str>) -> bool {
        self.hooks_inert_with(names, false)
    }

    /// `hooks_inert` for an operation that leaves the working tree as it is,
    /// such as a fetch: the shim of a hook manager that stops at once when the
    /// project has no such hook counts too, while Git reaches its directory
    /// through the repository's own `core.hooksPath` with no link on the way.
    pub(super) fn hooks_inert_in_a_stable_tree<'a>(
        &self,
        names: impl IntoIterator<Item = &'a str>,
    ) -> bool {
        self.hooks_inert_with(names, true)
    }

    /// `--git-path` honors `core.hooksPath` and the linked worktree layout.
    /// One `rev-parse` resolves every name; it prints one path per request.
    fn hooks_inert_with<'a>(
        &self,
        names: impl IntoIterator<Item = &'a str>,
        stable_tree: bool,
    ) -> bool {
        let mut arguments = vec!["rev-parse", "--path-format=absolute"];
        // Several writes may share a hook; ask for each path once.
        let mut hooks: Vec<&str> = Vec::new();
        for name in names {
            if !hooks.contains(&name) {
                hooks.push(name);
            }
        }
        if hooks.is_empty() {
            return true;
        }
        let requests = hooks
            .iter()
            .map(|name| format!("hooks/{name}"))
            .collect::<Vec<_>>();
        for request in &requests {
            arguments.extend(["--git-path", request.as_str()]);
        }
        let Some((status, output)) = self.run(true, &arguments, TEXT_LIMIT * requests.len() as u64)
        else {
            return false;
        };
        let Some(paths) = status
            .success()
            .then(|| lines(&output, requests.len()))
            .flatten()
        else {
            return false;
        };
        paths.iter().zip(&hooks).all(|(path, hook)| {
            let path = PathBuf::from(path);
            path.is_absolute()
                && super::git_hook_files::hook_file_inert(&path, hook, &|directory| {
                    stable_tree && self.hooks_directory_reached(directory)
                })
        })
    }

    /// The directory Git runs hooks from, whichever configuration names it, lies
    /// outside the checkout. An absolute or `~` value in the user's own
    /// configuration can still name a tracked directory of the checkout, to
    /// which an incoming commit adds a hook.
    pub(super) fn hooks_directory_outside_toplevel(&self) -> bool {
        let Some(top) = self
            .text(&["rev-parse", "--show-toplevel"])
            .and_then(|top| fs::canonicalize(top).ok())
        else {
            return false;
        };
        self.text(&["rev-parse", "--path-format=absolute", "--git-path", "hooks"])
            .is_some_and(|hooks| super::git_hook_files::outside_checkout(Path::new(&hooks), &top))
    }

    /// Git reaches `directory` through the repository's own relative
    /// `core.hooksPath` with no link on the way (see `git_hook_files`).
    fn hooks_directory_reached(&self, directory: &Path) -> bool {
        let Some(top) = self
            .text(&["rev-parse", "--show-toplevel"])
            .and_then(|top| fs::canonicalize(top).ok())
        else {
            return false;
        };
        let Some((effective, repository)) = self.config() else {
            return false;
        };
        let values = |config: &super::git_remote_config::GitConfig| {
            config.get("core.hookspath").cloned().unwrap_or_default()
        };
        super::git_hook_files::reached_without_a_link(
            &top,
            &values(&effective),
            &values(&repository),
            directory,
        )
    }

    /// Every configured credential helper resolves to a trusted executable.
    pub(super) fn credential_helpers_trusted(&self, helpers: &[&str]) -> bool {
        use super::git_remote_config::{credential_helper_shape, HelperShape};
        if helpers.is_empty() {
            return true;
        }
        let exec_path = self
            .run(false, &["--exec-path"], TEXT_LIMIT)
            .filter(|(status, _)| status.success())
            .and_then(|(_, output)| line(&output))
            .and_then(|path| fs::canonicalize(path).ok());
        let Some(exec_path) = exec_path else {
            return false;
        };
        helpers.iter().all(|helper| {
            let shape = credential_helper_shape(helper);
            let named = matches!(shape, Some(HelperShape::Named(_)));
            let resolved = match shape {
                Some(HelperShape::GithubCli("gh")) => super::git_config::trusted_command(
                    "gh",
                    &self.home,
                    &self.cwd,
                    Some(&self.environment),
                ),
                Some(HelperShape::GithubCli(path)) => fs::canonicalize(path).ok(),
                Some(HelperShape::Named(name)) => {
                    fs::canonicalize(exec_path.join(format!("git-credential-{name}")))
                        .ok()
                        .filter(|path| path.is_file())
                }
                None => None,
            };
            resolved.is_some_and(|path| {
                super::trusted_location::trusted_location(&path, &self.home, &self.cwd)
                    // Apple's Git keeps its helpers in an Xcode or Command
                    // Line Tools bundle that `/Applications` lets admins
                    // rename; root still owns every directory inside it.
                    || named && apple_developer_tools::bundled_helper(&path, &exec_path)
            })
        })
    }
}

fn line(output: &[u8]) -> Option<String> {
    let rendered = std::str::from_utf8(output).ok()?.trim();
    (!rendered.is_empty() && !rendered.contains(['\0', '\n', '\r'])).then(|| rendered.to_owned())
}

/// Exactly `count` lines, each one a value [`line`] accepts. A value that
/// itself held a line break shifts the count, so the whole answer is refused.
fn lines(output: &[u8], count: usize) -> Option<Vec<String>> {
    let rendered = std::str::from_utf8(output).ok()?;
    let rendered = rendered.strip_suffix('\n').unwrap_or(rendered);
    let values = rendered
        .split('\n')
        .map(|value| line(value.as_bytes()))
        .collect::<Option<Vec<_>>>()?;
    (values.len() == count).then_some(values)
}

#[cfg(test)]
mod tests {
    use super::lines;

    #[test]
    fn batched_paths_need_one_clean_line_per_request() {
        let both = Some(vec![
            "/r/.git/hooks/a".to_owned(),
            "/r/.git/hooks/b".to_owned(),
        ]);
        assert_eq!(lines(b"/r/.git/hooks/a\n/r/.git/hooks/b\n", 2), both);
        assert_eq!(lines(b"/r/.git/hooks/a\r\n/r/.git/hooks/b\r\n", 2), both);
        assert_eq!(lines(b"/r/.git/hooks/a\n", 2), None);
        assert_eq!(lines(b"/r/.git/hooks/a\n/r/x\ny/hooks/b\n", 2), None);
        assert_eq!(lines(b"/r/.git/hooks/a\n\n", 2), None);
        assert_eq!(lines(b"", 1), None);
    }
}
