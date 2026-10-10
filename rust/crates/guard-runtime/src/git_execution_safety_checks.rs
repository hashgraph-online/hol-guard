//! Git execution-safety verdicts. Every check fails closed: a missing binary,
//! a failed or timed-out probe, or an unparsable answer is a refusal.

use std::fs;
use std::path::{Path, PathBuf};

use guard_contracts::{GitExecutionSafetyCheckV1, GitExecutionSafetyRequestV1};

use crate::git_execution_safety_binary::{
    binary_path_is_trusted, exists_and_executable, global_config_environment_is_stable,
    resolve_trusted_git, trusted_global_push_hook, which_for_cwd,
};
use crate::git_execution_safety_config::{
    checkout_config_can_fetch, checkout_environment_is_set, credential_helper_shape,
    credential_helpers, fetch_config_routes_execution, fetch_environment_is_set, parse_null_config,
    push_config_routes_execution, push_effective_config_weakens_transport,
    push_scoped_config_routes_transport, routing_environment_is_clean,
    safe_github_https_remote_url, status_arguments_are_read_only, Environment, GitConfig,
    HelperShape,
};
use crate::git_execution_safety_probe::{ProbeOutput, Prober};

pub(crate) struct Verdict {
    pub(crate) allowed: bool,
    pub(crate) resolved_path: Option<String>,
}

impl Verdict {
    fn of(allowed: bool) -> Self {
        Self {
            allowed,
            resolved_path: None,
        }
    }
}

struct Context<'a> {
    request: &'a GitExecutionSafetyRequestV1,
    cwd: PathBuf,
    home: PathBuf,
    git: PathBuf,
}

pub(crate) fn decide(request: &GitExecutionSafetyRequestV1) -> Verdict {
    let environment = &request.environment;
    let cwd = Path::new(&request.cwd);
    let home = Path::new(&request.home);
    match request.check {
        GitExecutionSafetyCheckV1::StatusArguments => {
            return Verdict::of(status_arguments_are_read_only(&request.arguments));
        }
        GitExecutionSafetyCheckV1::ConfigEnvironmentClean => {
            return Verdict::of(routing_environment_is_clean(environment));
        }
        GitExecutionSafetyCheckV1::BinaryTrusted => {
            return Verdict::of(request.git_path.as_deref().is_some_and(|path| {
                binary_path_is_trusted(Path::new(path), cwd, home, &request.groups)
            }));
        }
        GitExecutionSafetyCheckV1::ResolveBinary => {
            let resolved = resolve_trusted_git(cwd, environment, home, &request.groups);
            return Verdict {
                allowed: resolved.is_some(),
                resolved_path: resolved.map(|path| path.to_string_lossy().into_owned()),
            };
        }
        _ => {}
    }
    if !cwd.is_absolute() || !home.is_absolute() {
        return Verdict::of(false);
    }
    let git = match request.git_binary.as_deref() {
        Some(path) => Some(PathBuf::from(path)),
        None => resolve_trusted_git(cwd, environment, home, &request.groups),
    };
    let Some(git) = git.filter(|path| path.is_absolute()) else {
        return Verdict::of(false);
    };
    let context = Context {
        request,
        cwd: cwd.to_path_buf(),
        home: home.to_path_buf(),
        git,
    };
    Verdict::of(match request.check {
        GitExecutionSafetyCheckV1::StatusConfig => context.status_config(),
        GitExecutionSafetyCheckV1::ObjectQuery => context.object_query(),
        GitExecutionSafetyCheckV1::FetchOrigin => context.fetch_origin(),
        GitExecutionSafetyCheckV1::PushOrigin => context.push_origin(),
        GitExecutionSafetyCheckV1::WorktreeAdd => context.worktree_add(),
        _ => false,
    })
}

fn pager_disabled(value: &str) -> bool {
    matches!(value, "" | "cat")
}

fn values(output: &ProbeOutput) -> Option<Vec<&str>> {
    Some(
        output
            .text()?
            .split('\0')
            .filter(|value| !value.is_empty())
            .collect(),
    )
}

impl Context<'_> {
    fn environment(&self) -> &Environment {
        &self.request.environment
    }

    fn prober<'a>(&'a self, cwd: &'a Path) -> Prober<'a> {
        Prober {
            git: &self.git,
            cwd,
            environment: self.environment(),
        }
    }

    fn config(&self, prober: &Prober<'_>) -> Option<GitConfig> {
        let output = prober.run(&["config", "--null", "--list"])?;
        if !output.success() {
            return None;
        }
        parse_null_config(output.text()?)
    }

    fn inside_work_tree(&self, prober: &Prober<'_>) -> bool {
        prober
            .run(&["rev-parse", "--is-inside-work-tree"])
            .is_some_and(|output| {
                output.success() && output.text().is_some_and(|text| text.trim() == "true")
            })
    }

    /// Git hook paths that exist and are executable make the operation unsafe.
    fn hooks_are_inert(&self, prober: &Prober<'_>, repository: &Path, names: &[&str]) -> bool {
        let mut arguments = vec!["rev-parse"];
        let hook_names: Vec<String> = names.iter().map(|name| format!("hooks/{name}")).collect();
        for name in &hook_names {
            arguments.extend(["--git-path", name.as_str()]);
        }
        let Some(output) = prober.run(&arguments) else {
            return false;
        };
        let Some(text) = output.text().filter(|_| output.success()) else {
            return false;
        };
        let paths: Vec<&str> = text.lines().collect();
        paths.len() == names.len()
            && paths.iter().all(|value| {
                let path = Path::new(value);
                let path = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    repository.join(path)
                };
                !exists_and_executable(&path)
            })
    }

    fn status_config(&self) -> bool {
        let environment = self.environment();
        if !routing_environment_is_clean(environment) {
            return false;
        }
        let prober = self.prober(&self.cwd);
        if let Some(pager) = environment.get("GIT_PAGER") {
            if !pager_disabled(pager) {
                return false;
            }
        } else {
            if !pager_disabled(environment.get("PAGER").map_or("", String::as_str)) {
                return false;
            }
            for key in ["core.pager", "pager.status"] {
                let Some(output) = prober.run(&["config", "--null", "--get-all", key]) else {
                    return false;
                };
                if output.code == Some(1) && output.stdout.is_empty() {
                    continue;
                }
                if !output.success() {
                    return false;
                }
                match values(&output) {
                    Some(found) if found.iter().all(|value| *value == "cat") => {}
                    _ => return false,
                }
            }
        }
        let Some(output) = prober.run(&["config", "--null", "--get-all", "core.fsmonitor"]) else {
            return false;
        };
        if output.code == Some(1) && output.stdout.is_empty() {
            return true;
        }
        if !output.success() {
            return false;
        }
        let Some(found) = output.text() else {
            return false;
        };
        let found: Vec<String> = found
            .split('\0')
            .map(|value| value.trim().to_lowercase())
            .filter(|value| !value.is_empty())
            .collect();
        !found.is_empty()
            && found
                .iter()
                .all(|value| matches!(value.as_str(), "0" | "false" | "no" | "off"))
    }

    fn object_query(&self) -> bool {
        if !routing_environment_is_clean(self.environment()) {
            return false;
        }
        let Ok(repository) = fs::canonicalize(&self.cwd) else {
            return false;
        };
        let prober = self.prober(&repository);
        self.inside_work_tree(&prober)
            && self
                .config(&prober)
                .is_some_and(|config| !checkout_config_can_fetch(&config))
    }

    fn fetch_origin(&self) -> bool {
        let environment = self.environment();
        if !routing_environment_is_clean(environment) || fetch_environment_is_set(environment) {
            return false;
        }
        let Ok(repository) = fs::canonicalize(&self.cwd) else {
            return false;
        };
        let prober = self.prober(&repository);
        if !self.inside_work_tree(&prober) {
            return false;
        }
        let Some(config) = self.config(&prober) else {
            return false;
        };
        if fetch_config_routes_execution(&config) {
            return false;
        }
        match config.get("remote.origin.url") {
            Some(urls) if urls.iter().all(|url| safe_github_https_remote_url(url)) => {}
            _ => return false,
        }
        let exec_path = prober
            .run(&["--exec-path"])
            .filter(ProbeOutput::success)
            .and_then(|output| output.text().map(|text| text.trim().to_owned()))
            .and_then(|path| fs::canonicalize(path).ok());
        let Some(exec_path) = exec_path else {
            return false;
        };
        if !credential_helpers(&config)
            .iter()
            .all(|helper| self.trusted_credential_helper(helper, &exec_path, &repository))
        {
            return false;
        }
        self.hooks_are_inert(
            &prober,
            &repository,
            &["post-fetch", "pre-auto-gc", "reference-transaction"],
        )
    }

    fn trusted_credential_helper(&self, value: &str, exec_path: &Path, cwd: &Path) -> bool {
        let home = &self.home;
        let resolved = match credential_helper_shape(value) {
            Some(HelperShape::GithubCli("gh")) => {
                which_for_cwd("gh", cwd, self.environment(), home)
                    .and_then(|path| fs::canonicalize(path).ok())
            }
            Some(HelperShape::GithubCli(path)) => fs::canonicalize(path).ok(),
            Some(HelperShape::Named(name)) => {
                fs::canonicalize(exec_path.join(format!("git-credential-{name}")))
                    .ok()
                    .filter(|path| path.is_file())
            }
            None => None,
        };
        resolved.is_some_and(|path| binary_path_is_trusted(&path, cwd, home, &self.request.groups))
    }

    fn push_origin(&self) -> bool {
        let Some(branch) = self
            .request
            .branch
            .as_deref()
            .filter(|branch| !branch.is_empty() && !branch.starts_with('-'))
        else {
            return false;
        };
        if !global_config_environment_is_stable(
            self.environment(),
            self.request.account_home.as_deref(),
        ) || !self.fetch_origin()
        {
            return false;
        }
        let Ok(repository) = fs::canonicalize(&self.cwd) else {
            return false;
        };
        let prober = self.prober(&repository);
        let echoes = |arguments: &[&str]| {
            prober
                .run(arguments)
                .filter(ProbeOutput::success)
                .and_then(|output| output.text().map(|text| text.trim() == branch))
                .unwrap_or(false)
        };
        if !echoes(&["check-ref-format", "--branch", branch])
            || !echoes(&["symbolic-ref", "--quiet", "--short", "HEAD"])
        {
            return false;
        }
        let scoped = |arguments: &[&str]| -> Option<GitConfig> {
            let output = prober.run(arguments)?;
            if !matches!(output.code, Some(0 | 1)) {
                return None;
            }
            parse_null_config(output.text()?)
        };
        let (Some(config), Some(local), Some(worktree)) = (
            self.config(&prober),
            scoped(&["config", "--local", "--null", "--list"]),
            scoped(&["config", "--worktree", "--null", "--list"]),
        ) else {
            return false;
        };
        if push_config_routes_execution(&config, branch)
            || push_effective_config_weakens_transport(&config)
            || push_scoped_config_routes_transport(&local)
            || push_scoped_config_routes_transport(&worktree)
            || local.contains_key("core.hookspath")
            || worktree.contains_key("core.hookspath")
            || config.get("remote.origin.url").map_or(0, Vec::len) != 1
        {
            return false;
        }
        let Some(hook) = prober
            .run(&["rev-parse", "--git-path", "hooks/pre-push"])
            .filter(ProbeOutput::success)
            .and_then(|output| output.text().map(|text| text.trim().to_owned()))
        else {
            return false;
        };
        let hook = Path::new(&hook);
        let hook = if hook.is_absolute() {
            hook.to_path_buf()
        } else {
            repository.join(hook)
        };
        if !exists_and_executable(&hook) {
            return true;
        }
        let linked = fs::symlink_metadata(&hook).map(|link| link.file_type().is_symlink());
        if !config.contains_key("core.hookspath") || linked.unwrap_or(true) {
            return false;
        }
        fs::canonicalize(&hook).is_ok_and(|resolved| {
            resolved == hook && trusted_global_push_hook(&resolved, &repository)
        })
    }

    fn worktree_add(&self) -> bool {
        if checkout_environment_is_set(self.environment()) || !self.status_config() {
            return false;
        }
        let Ok(repository) = fs::canonicalize(&self.cwd) else {
            return false;
        };
        let prober = self.prober(&repository);
        let Some(config) = self.config(&prober) else {
            return false;
        };
        let filters_configured = config.iter().any(|(key, values)| {
            key.starts_with("filter.")
                && [".clean", ".smudge", ".process"]
                    .iter()
                    .any(|suffix| key.ends_with(suffix))
                && values.iter().any(|value| !value.trim().is_empty())
        });
        let reference = self.request.reference.as_deref().unwrap_or("HEAD");
        if checkout_config_can_fetch(&config)
            || (filters_configured && self.ref_uses_checkout_filter(&prober, reference))
        {
            return false;
        }
        self.hooks_are_inert(
            &prober,
            &repository,
            &["post-checkout", "reference-transaction"],
        )
    }

    fn ref_uses_checkout_filter(&self, prober: &Prober<'_>, reference: &str) -> bool {
        if reference.starts_with('-') {
            return true;
        }
        let Some(files) = prober
            .run(&["ls-tree", "-r", "--name-only", "-z", reference])
            .filter(ProbeOutput::success)
        else {
            return true;
        };
        let source = format!("--source={reference}");
        let Some(attributes) = prober
            .run_with_input(
                &["check-attr", "-z", "--stdin", &source, "filter"],
                Some(files.stdout),
            )
            .filter(ProbeOutput::success)
        else {
            return true;
        };
        let mut fields: Vec<&[u8]> = attributes.stdout.split(|byte| *byte == 0).collect();
        if fields.last().is_some_and(|last| last.is_empty()) {
            fields.pop();
        }
        fields.len() % 3 != 0
            || fields
                .iter()
                .skip(2)
                .step_by(3)
                .any(|value| !matches!(*value, b"unspecified" | b"unset"))
    }
}

/// Exposed to tests: filter detection against a prepared repository.
#[cfg(all(test, unix))]
pub(crate) fn ref_uses_checkout_filter_for_tests(
    request: &GitExecutionSafetyRequestV1,
    git: &Path,
    cwd: &Path,
    reference: &str,
) -> bool {
    let context = Context {
        request,
        cwd: cwd.to_path_buf(),
        home: PathBuf::from(&request.home),
        git: git.to_path_buf(),
    };
    context.ref_uses_checkout_filter(&context.prober(cwd), reference)
}
