use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{json, Value};

use super::super::context::{Engines, LocalExecution, ResidentEngines};
use super::super::reasons::{COMPOUND_COMMAND, MUTABLE_LAUNCHER, UNPROVEN_LAUNCH};
use super::super::reuse_shape::is_simple;
use super::{env_state, settings_and_program};
use crate::mcp_proxy_shlex::split_with;

/// Launch identities that depend on nothing but the spelled program.
struct Spelled;

impl Engines for Spelled {
    fn launch_identity(
        &self,
        executable: &str,
        args: &[String],
        cwd: &str,
        _home: Option<&str>,
        env: &BTreeMap<String, String>,
    ) -> Value {
        json!({"executable": executable, "args": args, "cwd": cwd, "path": env.get("PATH")})
    }

    fn launch_reusable(&self, identity: &Value) -> bool {
        !identity["executable"]
            .as_str()
            .unwrap_or("")
            .contains("unreusable")
    }

    fn local_executions(
        &self,
        _command: &str,
        _cwd: &str,
        _home: Option<&str>,
        _env: &BTreeMap<String, String>,
    ) -> Option<Vec<LocalExecution>> {
        None
    }
}

/// An engine whose `env` binary can be swapped without moving the lookup path.
struct SwappableEnv(AtomicUsize);

impl Engines for SwappableEnv {
    fn launch_identity(
        &self,
        executable: &str,
        args: &[String],
        cwd: &str,
        home: Option<&str>,
        env: &BTreeMap<String, String>,
    ) -> Value {
        let mut identity = Spelled.launch_identity(executable, args, cwd, home, env);
        if executable == "env" {
            identity["content"] = json!(self.0.load(Ordering::Relaxed));
        }
        identity
    }

    fn launch_reusable(&self, identity: &Value) -> bool {
        Spelled.launch_reusable(identity)
    }

    fn local_executions(
        &self,
        command: &str,
        cwd: &str,
        home: Option<&str>,
        env: &BTreeMap<String, String>,
    ) -> Option<Vec<LocalExecution>> {
        Spelled.local_executions(command, cwd, home, env)
    }
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "env-launch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }

    fn cwd(&self) -> String {
        self.0.to_string_lossy().into_owned()
    }

    fn script(&self, name: &str, body: &str) {
        let path = self.0.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn environment(digest: &str) -> Value {
    json!({
        "path": "/usr/bin:/bin",
        "home": "/home/agent",
        "environment_names": ["HOME", "PATH"],
        "environment_digest": digest.repeat(64),
    })
}

fn state_in(scratch: &Scratch, command: &str, environment: &Value) -> Result<String, &'static str> {
    env_state(command, &scratch.cwd(), Some(environment), &Spelled)
}

fn program(command: &str) -> Result<Vec<String>, &'static str> {
    let words = split_with(command, ";&|<>", "#").unwrap();
    settings_and_program(&words).map(|(_, program)| program.to_vec())
}

#[test]
fn plain_settings_before_one_program_are_bindable_in_both_spellings() {
    for command in [
        "DEPLOY_ALLOW_BACKGROUND=1 ./scripts/release.sh production",
        "env DEPLOY_ALLOW_BACKGROUND=1 ./scripts/release.sh production",
        "FOO=1 BAR=two ./scripts/release.sh production",
        "env FOO=1 BAR=two ./scripts/release.sh production",
    ] {
        assert_eq!(
            program(command),
            Ok(vec![
                "./scripts/release.sh".to_owned(),
                "production".to_owned()
            ]),
            "{command}"
        );
    }
}

#[test]
fn a_command_that_is_not_plain_settings_before_one_program_is_not_bound() {
    for command in [
        "./scripts/release.sh production",
        "env ./scripts/release.sh",
        "FOO=1",
        "env FOO=1",
        "env -i FOO=1 ./scripts/release.sh",
        "env -u HOME FOO=1 ./scripts/release.sh",
        "env -S 'FOO=1 ./run' ./scripts/release.sh",
        "env FOO=1 env BAR=1 ./scripts/release.sh",
        "FOO=1 FOO=2 ./scripts/release.sh",
        "FOO=1 foo=2 ./scripts/release.sh",
        "FOO=1 -x ./scripts/release.sh",
        "FOO=1 BAR-X=1 ./scripts/release.sh",
        "FOO=1 A=1 B=1 C=1 D=1 E=1 F=1 G=1 H=1 I=1 ./scripts/release.sh",
    ] {
        assert_eq!(program(command), Err(MUTABLE_LAUNCHER), "{command}");
    }
}

#[test]
fn settings_that_reroute_load_or_carry_authority_are_not_bound() {
    for command in [
        "PATH=/tmp/bin ./scripts/release.sh",
        "HOME=/tmp/home ./scripts/release.sh",
        "BASH_ENV=/tmp/rc ./scripts/release.sh",
        "LD_PRELOAD=/tmp/x.so ./scripts/release.sh",
        "DYLD_INSERT_LIBRARIES=/tmp/x.dylib ./scripts/release.sh",
        "NODE_OPTIONS=--max-old-space-size=4096 ./scripts/release.sh",
        "NODE_PATH=/work/node_modules ./scripts/release.sh",
        "GIT_SSH_COMMAND=ssh ./scripts/release.sh",
        "HOL_GUARD_HOME=/tmp/g ./scripts/release.sh",
        "RELEASE_TOKEN=abc ./scripts/release.sh",
        "HTTPS_PROXY=proxy ./scripts/release.sh",
        "FOO=/etc/hosts ./scripts/release.sh",
        "FOO=a;b ./scripts/release.sh",
    ] {
        let words = split_with(command, ";&|<>", "#").unwrap();
        assert!(
            !is_simple(&words) || settings_and_program(&words).is_err(),
            "{command}"
        );
    }
}

#[test]
fn shell_expansion_and_compound_text_is_not_bound() {
    let scratch = Scratch::new();
    let environment = environment("a");
    for command in [
        "FOO=$BAR ./scripts/release.sh",
        "FOO=1 ./scripts/release.sh $TARGET",
        "FOO=1 ./scripts/release.sh $(whoami)",
        "FOO=1 ./scripts/release.sh `whoami`",
        "FOO=1 ./scripts/release.sh ~/x",
        "FOO=1 ./scripts/release.sh *.log",
        "FOO=1 ./scripts/release.sh a?",
        "FOO=1 ./scripts/release.sh {a,b}",
        "FOO=1 ./scripts/release.sh # note",
        "FOO=1 ./scripts/release.sh \\\nmore",
    ] {
        assert_eq!(
            state_in(&scratch, command, &environment),
            Err(MUTABLE_LAUNCHER),
            "{command}"
        );
    }
    for command in [
        "FOO=1 ./scripts/release.sh && rm -rf build",
        "FOO=1 ./scripts/release.sh | tee log",
        "FOO=1 ./scripts/release.sh; ls",
        "FOO=1 ./scripts/release.sh > out.txt",
    ] {
        assert_eq!(
            state_in(&scratch, command, &environment),
            Err(COMPOUND_COMMAND),
            "{command}"
        );
    }
}

#[test]
fn a_request_without_the_agents_stamped_environment_is_not_bound() {
    let scratch = Scratch::new();
    let command = "FOO=1 ./scripts/release.sh production";
    assert_eq!(
        env_state(command, &scratch.cwd(), None, &Spelled),
        Err(UNPROVEN_LAUNCH)
    );
    for malformed in [
        json!({"path": 7}),
        json!({"path": "/bin", "environment_names": [], "environment_digest": "short"}),
        // A well-formed environment that names no home.
        json!({"path": "/bin", "environment_names": [], "environment_digest": "a".repeat(64)}),
    ] {
        assert_eq!(
            env_state(command, &scratch.cwd(), Some(&malformed), &Spelled),
            Err(UNPROVEN_LAUNCH),
            "{malformed}"
        );
    }
}

#[test]
fn the_binding_changes_with_anything_the_approval_must_not_cover() {
    let scratch = Scratch::new();
    let elsewhere = Scratch::new();
    let base = environment("a");
    let command = "FOO=1 ./scripts/release.sh production";
    let approved = state_in(&scratch, command, &base).unwrap();
    assert_eq!(approved, state_in(&scratch, command, &base).unwrap());
    let moved_path = json!({
        "path": "/opt/bin:/usr/bin",
        "home": "/home/agent",
        "environment_names": ["HOME", "PATH"],
        "environment_digest": "a".repeat(64),
    });
    for (label, other) in [
        (
            "another value",
            state_in(&scratch, "FOO=2 ./scripts/release.sh production", &base),
        ),
        (
            "another setting",
            state_in(
                &scratch,
                "FOO=1 BAR=1 ./scripts/release.sh production",
                &base,
            ),
        ),
        (
            "another argument",
            state_in(&scratch, "FOO=1 ./scripts/release.sh staging", &base),
        ),
        (
            "another program",
            state_in(&scratch, "FOO=1 ./scripts/other.sh production", &base),
        ),
        (
            "the env spelling",
            state_in(&scratch, "env FOO=1 ./scripts/release.sh production", &base),
        ),
        (
            "another agent environment",
            state_in(&scratch, command, &environment("b")),
        ),
        (
            "another lookup path",
            state_in(&scratch, command, &moved_path),
        ),
        (
            "another working directory",
            state_in(&elsewhere, command, &base),
        ),
    ] {
        assert!(other.is_ok(), "{label}");
        assert_ne!(other.unwrap(), approved, "{label}");
    }
}

#[test]
fn a_program_the_launch_proof_cannot_bind_is_not_approvable_by_settings() {
    let scratch = Scratch::new();
    let environment = environment("a");
    for command in [
        "FOO=1 ./unreusable.sh",
        "FOO=1 bash ./scripts/release.sh",
        "FOO=1 sh -c 'echo hi'",
        "FOO=1 make deploy",
        "FOO=1 npm run release",
    ] {
        assert!(
            state_in(&scratch, command, &environment).is_err(),
            "{command}"
        );
    }
}

#[test]
fn an_approved_script_is_bound_to_its_content() {
    let scratch = Scratch::new();
    scratch.script("release.sh", "#!/bin/sh\necho one\n");
    let environment = json!({
        "path": "/usr/bin:/bin",
        "home": scratch.cwd(),
        "environment_names": ["HOME", "PATH"],
        "environment_digest": "c".repeat(64),
    });
    let command = "DEPLOY_ALLOW_BACKGROUND=1 ./release.sh production";
    let bind = |command: &str| {
        env_state(
            command,
            &scratch.cwd(),
            Some(&environment),
            &ResidentEngines { guard_home: None },
        )
    };
    let first = bind(command).unwrap();
    assert_eq!(first, bind(command).unwrap());
    assert_ne!(
        first,
        bind("DEPLOY_ALLOW_BACKGROUND=0 ./release.sh production").unwrap()
    );
    scratch.script("release.sh", "#!/bin/sh\necho two\n");
    assert_ne!(first, bind(command).unwrap());
}

#[test]
fn a_quoted_word_that_looks_like_a_setting_is_not_bound() {
    let scratch = Scratch::new();
    let environment = environment("a");
    for command in [
        "'FOO=1' ./scripts/release.sh production",
        "\"FOO=1\" ./scripts/release.sh production",
        "FOO='1' ./scripts/release.sh production",
        "FOO=\"1\" ./scripts/release.sh production",
        "'FOO'=1 ./scripts/release.sh production",
        "env 'FOO=1' ./scripts/release.sh production",
        "'env' FOO=1 ./scripts/release.sh production",
    ] {
        assert_eq!(
            state_in(&scratch, command, &environment),
            Err(MUTABLE_LAUNCHER),
            "{command}"
        );
    }
    // Quoting the program or an argument does not change what the settings mean.
    assert!(state_in(
        &scratch,
        "FOO=1 './scripts/release.sh' 'production'",
        &environment
    )
    .is_ok());
}

#[test]
fn the_env_binary_is_bound_only_when_the_command_spells_it() {
    let scratch = Scratch::new();
    let environment = environment("a");
    let engine = SwappableEnv(AtomicUsize::new(0));
    let bind = |command: &str| env_state(command, &scratch.cwd(), Some(&environment), &engine);
    let with_env = bind("env FOO=1 ./scripts/release.sh production").unwrap();
    let bare = bind("FOO=1 ./scripts/release.sh production").unwrap();
    engine.0.store(1, Ordering::Relaxed);
    assert_ne!(
        with_env,
        bind("env FOO=1 ./scripts/release.sh production").unwrap()
    );
    assert_eq!(bare, bind("FOO=1 ./scripts/release.sh production").unwrap());
    // An `env` the proof cannot call reusable is not approvable.
    struct Unreusable;
    impl Engines for Unreusable {
        fn launch_identity(
            &self,
            executable: &str,
            args: &[String],
            cwd: &str,
            home: Option<&str>,
            env: &BTreeMap<String, String>,
        ) -> Value {
            let mut identity = Spelled.launch_identity(executable, args, cwd, home, env);
            if executable == "env" {
                identity["executable"] = json!("unreusable-env");
            }
            identity
        }
        fn launch_reusable(&self, identity: &Value) -> bool {
            Spelled.launch_reusable(identity)
        }
        fn local_executions(
            &self,
            _command: &str,
            _cwd: &str,
            _home: Option<&str>,
            _env: &BTreeMap<String, String>,
        ) -> Option<Vec<LocalExecution>> {
            None
        }
    }
    assert_eq!(
        env_state(
            "env FOO=1 ./scripts/release.sh",
            &scratch.cwd(),
            Some(&environment),
            &Unreusable
        ),
        Err(UNPROVEN_LAUNCH)
    );
}

#[test]
fn a_file_named_by_a_setting_is_bound_to_its_content() {
    let scratch = Scratch::new();
    let environment = environment("a");
    let command = "FOO=deploy.yaml ./scripts/release.sh production";
    let absent = state_in(&scratch, command, &environment).unwrap();
    std::fs::write(scratch.0.join("deploy.yaml"), "target: staging\n").unwrap();
    let first = state_in(&scratch, command, &environment).unwrap();
    assert_ne!(absent, first);
    assert_eq!(first, state_in(&scratch, command, &environment).unwrap());
    std::fs::write(scratch.0.join("deploy.yaml"), "target: production\n").unwrap();
    assert_ne!(first, state_in(&scratch, command, &environment).unwrap());
    // A value that names a directory binds no content, so it is not approvable.
    std::fs::create_dir(scratch.0.join("conf")).unwrap();
    for command in [
        "FOO=conf ./scripts/release.sh",
        "FOO=. ./scripts/release.sh",
        "FOO=.. ./scripts/release.sh",
    ] {
        assert_eq!(
            state_in(&scratch, command, &environment),
            Err(MUTABLE_LAUNCHER),
            "{command}"
        );
    }
}
