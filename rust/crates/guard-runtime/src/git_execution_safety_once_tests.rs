//! Real-Git repositories for the one-time push approval state.
use std::path::{Path, PathBuf};
use std::process::Command;

use guard_contracts::{
    GitExecutionSafetyCheckV1 as Check, GitExecutionSafetyRequestV1,
    GIT_EXECUTION_SAFETY_REQUEST_SCHEMA,
};
use serde_json::Value;

use super::{
    config_origins, directory_files, push_once_state, ssh_config_runs_no_program, transport,
    Transport, SYSTEM_SSH_CONFIG, SYSTEM_SSH_CONFIG_DIR,
};
use crate::git_execution_safety_binary::{binary_path_is_trusted, which_for_cwd};

fn git(repository: &Path, home: &Path, arguments: &[&str]) -> String {
    let mut command = Command::new("git");
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_NAMESPACE",
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "XDG_CONFIG_HOME",
    ] {
        command.env_remove(name);
    }
    let output = command
        .args(arguments)
        .current_dir(repository)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()
        .unwrap();
    assert!(output.status.success(), "git {arguments:?}: {output:?}");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn caller_groups() -> Vec<u32> {
    let output = Command::new("id").arg("-G").output().unwrap();
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter_map(|group| group.parse().ok())
        .collect()
}

/// A repository on `main` whose origin is a self-hosted ssh remote.
struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    repository: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let (home, repository) = (root.join("home"), root.join("repo"));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&repository).unwrap();
        git(&repository, &home, &["init", "-q", "--initial-branch=main"]);
        git(
            &repository,
            &home,
            &["commit", "-q", "--allow-empty", "-m", "one"],
        );
        let origin = "ssh://git@git.example.invalid:30009/team/app.git";
        git(&repository, &home, &["remote", "add", "origin", origin]);
        Self {
            _dir: dir,
            home,
            repository,
        }
    }

    fn git(&self, arguments: &[&str]) -> String {
        git(&self.repository, &self.home, arguments)
    }

    fn request(&self) -> GitExecutionSafetyRequestV1 {
        let home = self.home.to_string_lossy().into_owned();
        GitExecutionSafetyRequestV1 {
            schema: GIT_EXECUTION_SAFETY_REQUEST_SCHEMA.to_owned(),
            request_id: "test".to_owned(),
            check: Check::PushOrigin,
            cwd: self.repository.to_string_lossy().into_owned(),
            home: home.clone(),
            account_home: Some(home.clone()),
            groups: caller_groups(),
            environment: [
                ("PATH".to_owned(), std::env::var("PATH").unwrap_or_default()),
                ("HOME".to_owned(), home),
            ]
            .into_iter()
            .collect(),
            git_binary: None,
            git_path: None,
            arguments: Vec::new(),
            branch: Some("main".to_owned()),
            reference: None,
        }
    }

    fn state(&self) -> Option<Value> {
        push_once_state(&self.request())
    }

    /// Whether this host's Git can prove a push at all: a trusted binary that
    /// answers `git var GIT_CONFIG_SYSTEM` (Git 2.42 and later). Elsewhere the
    /// state must fail closed.
    fn host_can_prove(&self) -> bool {
        let trusted = crate::git_execution_safety_checks::decide(&GitExecutionSafetyRequestV1 {
            check: Check::ResolveBinary,
            ..self.request()
        })
        .allowed;
        let answers = Command::new("git")
            .args(["var", "GIT_CONFIG_SYSTEM"])
            .output()
            .is_ok_and(|output| output.status.success());
        if !(trusted && answers) {
            eprintln!("SKIPPED: host git is untrusted or too old to name its config files");
            assert!(self.state().is_none());
        }
        trusted && answers
    }

    /// Whether this host's own ssh can be bound: a trusted `ssh` on `PATH`
    /// and system client configs that run no program. Elsewhere the state
    /// must fail closed.
    fn host_ssh_can_bind(&self) -> bool {
        let request = self.request();
        let ssh = which_for_cwd("ssh", &self.repository, &request.environment, &self.home)
            .and_then(|path| std::fs::canonicalize(path).ok());
        let trusted = ssh.as_deref().is_some_and(|path| {
            binary_path_is_trusted(path, &self.repository, &self.home, &request.groups)
        });
        let mut files = vec![(SYSTEM_SSH_CONFIG.to_owned(), true)];
        let directory = directory_files(SYSTEM_SSH_CONFIG_DIR);
        files.extend(directory.iter().flatten().map(|path| (path.clone(), false)));
        let running: Vec<String> = files
            .into_iter()
            // A config the binding cannot read refuses it as well.
            .filter(|(path, include)| match std::fs::read(path) {
                Ok(data) => !ssh_config_runs_no_program(&String::from_utf8_lossy(&data), *include),
                Err(error) => error.kind() != std::io::ErrorKind::NotFound,
            })
            .map(|(path, _)| path)
            .collect();
        // Printed on failure, so a host this cannot bind names its reason.
        eprintln!(
            "host ssh {ssh:?} trusted={trusted}; {SYSTEM_SSH_CONFIG_DIR} {directory:?}; \
             configs that run a program or cannot be read: {running:?}"
        );
        let bindable = trusted && directory.is_some() && running.is_empty();
        if !bindable {
            eprintln!("SKIPPED: host ssh cannot be bound");
            assert!(self.state().is_none());
        }
        bindable
    }
}

#[test]
fn a_self_hosted_ssh_origin_is_bound_to_what_the_push_reads() {
    let fixture = Fixture::new();
    if !fixture.host_can_prove() || !fixture.host_ssh_can_bind() {
        return;
    }
    let state = fixture.state().expect("a plain ssh push is bindable");
    assert_eq!(fixture.state(), Some(state.clone()), "stable");
    assert_eq!(state["branch"], "main");
    assert_eq!(state["commit"], fixture.git(&["rev-parse", "main"]).trim());
    assert!(state["transport"]["ssh"]["sha256"].is_string(), "{state}");
    // Git's own answer for its system config, wherever its prefix put it.
    let output = Command::new("git")
        .args(["var", "GIT_CONFIG_SYSTEM"])
        .env_remove("GIT_CONFIG_NOSYSTEM")
        .output()
        .unwrap();
    let system = String::from_utf8_lossy(&output.stdout);
    assert!(
        state["config_files"]
            .as_object()
            .unwrap()
            .contains_key(system.trim()),
        "{state}"
    );
}

#[test]
fn https_pins_the_transport_helper_git_runs() {
    let fixture = Fixture::new();
    if !fixture.host_can_prove() {
        return;
    }
    let origin = "https://git.example.invalid/team/app.git";
    fixture.git(&["remote", "set-url", "origin", origin]);
    let state = fixture
        .state()
        .expect("a credential-free https push is bindable");
    let exec_path = fixture.git(&["--exec-path"]);
    let helper = Path::new(exec_path.trim()).join("git-remote-https");
    let resolved = helper.canonicalize().unwrap();
    assert_eq!(
        state["transport"]["helper"]["path"],
        resolved.to_string_lossy().as_ref()
    );
    assert!(state["transport"]["helper"]["sha256"].is_string());
}

#[test]
fn every_change_to_what_the_push_sends_or_runs_moves_the_state() {
    let fixture = Fixture::new();
    if !fixture.host_can_prove() || !fixture.host_ssh_can_bind() {
        return;
    }
    let before = fixture.state().unwrap();
    fixture.git(&["commit", "-q", "--allow-empty", "-m", "two"]);
    let committed = fixture.state().unwrap();
    assert_ne!(committed, before, "a new commit needs a new approval");
    fixture.git(&["config", "push.default", "current"]);
    assert_ne!(
        fixture.state().unwrap(),
        committed,
        "any effective config change"
    );
}

#[test]
fn what_the_native_push_proof_refuses_leaves_the_push_unbound() {
    for (key, value) in [
        // The review's shell-injection case: Git runs helpers through a shell.
        (
            "credential.helper",
            "store --file=/tmp/cred;touch /tmp/marker",
        ),
        ("credential.helper", "cache --timeout=1"),
        ("credential.helper", "!evil"),
        ("push.followTags", "true"),
        ("push.gpgSign", "true"),
        ("push.recurseSubmodules", "on-demand"),
        ("hook.pre-push.command", "evil"),
        ("core.sshCommand", "ssh -o ProxyCommand=evil"),
        ("core.askPass", "/tmp/askpass"),
        ("remote.origin.receivepack", "/tmp/receive"),
        ("remote.origin.pushurl", "ssh://git@other.invalid/app.git"),
        (
            "url.ssh://git@other.invalid/.pushInsteadOf",
            "ssh://git@git.example.invalid:30009/",
        ),
        ("http.sslVerify", "false"),
    ] {
        let fixture = Fixture::new();
        if !fixture.host_can_prove() {
            return;
        }
        fixture.git(&["config", key, value]);
        assert!(fixture.state().is_none(), "{key}={value}");
    }
}

#[test]
fn an_active_push_hook_or_another_remote_leaves_the_push_unbound() {
    let fixture = Fixture::new();
    if !fixture.host_can_prove() {
        return;
    }
    let hook = fixture.repository.join(".git/hooks/pre-push");
    std::fs::write(&hook, "#!/bin/sh\nnpm test\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert!(fixture.state().is_none(), "an executable pre-push hook");
    std::fs::remove_file(&hook).unwrap();
    for origin in [
        "/srv/git/app.git",
        "file:///srv/git/app.git",
        "git://git.example.invalid/app.git",
        "https://user:token@git.example.invalid/app.git",
        "ext::ssh -o ProxyCommand=evil host",
    ] {
        fixture.git(&["remote", "set-url", "origin", origin]);
        assert!(fixture.state().is_none(), "{origin}");
    }
}

#[test]
fn only_plain_ssh_and_https_urls_select_a_transport() {
    for (url, expected) in [
        (
            "ssh://git@host.example:30009/team/app.git",
            Some(Transport::Ssh),
        ),
        ("git@host.example:team/app.git", Some(Transport::Ssh)),
        ("host.example:/srv/app.git", Some(Transport::Ssh)),
        ("https://host.example/team/app.git", Some(Transport::Https)),
        ("https://user@host.example/app.git", None),
        ("http://host.example/app.git", None),
        ("ssh://-oProxyCommand=evil/app.git", None),
        ("-oProxyCommand=evil:app.git", None),
        ("host.example:-app.git", None),
        ("ssh://host.example/app.git?x", None),
        ("../app.git", None),
        ("evil::https://host.example/app.git", None),
        ("ssh://host.example/a\u{e9}.git", None),
    ] {
        assert_eq!(transport(url), expected, "{url}");
    }
}

#[test]
fn ssh_config_that_runs_a_program_fails_closed_even_when_quoted() {
    for text in [
        "Host *\n    ProxyCommand nc %h %p\n",
        "Host *\n    \"ProxyCommand\" sh -c evil\n",
        "Host *\n    Pro\"xyCommand\" sh -c evil\n",
        "Host *\n    ProxyCommand=nc %h %p\n",
        "Match host x \"exec\" evil\n",
        "Match host x !exec evil\n",
        "Host *\n    LocalCommand evil\n",
        "Host *\n    KnownHostsCommand evil\n",
        "Host *\n    PKCS11Provider /tmp/lib.so\n",
        "Host *\n    SecurityKeyProvider /tmp/sk.so\n",
        "\"Include\" ~/.ssh/extra\n",
        "Host *\n    ForwardX11 yes\n",
        "Host *\n    ForwardX11=yes\n",
    ] {
        assert!(!ssh_config_runs_no_program(text, false), "{text}");
    }
    assert!(ssh_config_runs_no_program(
        "Host git.example.invalid\n    Port 30009\n    User git\n",
        false
    ));
    // XQuartz adds `XAuthLocation` to the system config; without X11
    // forwarding ssh never runs it.
    assert!(ssh_config_runs_no_program(
        "Host *\n    XAuthLocation /opt/X11/bin/xauth\n    ForwardX11 no\n",
        false
    ));
    let system = "Include /etc/ssh/ssh_config.d/*.conf\nHost *\n    SendEnv LANG LC_*\n";
    assert!(ssh_config_runs_no_program(system, true));
    assert!(!ssh_config_runs_no_program(system, false));
}

#[test]
fn a_config_value_not_read_from_a_file_fails_closed() {
    let repository = Path::new("/work/app");
    let shown = "file:.git/config\0core.bare\nfalse\0file:/home/u/.gitconfig\0user.name\nu\0";
    assert_eq!(
        config_origins(shown, repository),
        Some(vec![
            "/work/app/.git/config".to_owned(),
            "/home/u/.gitconfig".to_owned()
        ])
    );
    assert_eq!(
        config_origins("command line:\0core.pager\nevil\0", repository),
        None
    );
    assert_eq!(
        config_origins("blob:abc\0core.pager\nevil\0", repository),
        None
    );
}
