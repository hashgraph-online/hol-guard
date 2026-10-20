use serde_json::json;

use super::super::reasons::{
    COMPOUND_COMMAND, GIT_HELPER_CONFIG, MUTABLE_LAUNCHER, UNPROVEN_LAUNCH,
};
use super::{push_state, pushed_branch};
use crate::mcp_proxy_shlex::split_with;

fn branch(command: &str) -> Result<String, &'static str> {
    let words = split_with(command, ";&|<>", "#").unwrap();
    pushed_branch(&words).map(str::to_owned)
}

#[test]
fn only_a_plain_push_of_one_branch_to_origin_is_a_bindable_shape() {
    for (command, expected) in [
        ("git push origin dev", "dev"),
        ("git push -u origin feature/login", "feature/login"),
        (
            "git push --set-upstream origin release-2026",
            "release-2026",
        ),
    ] {
        assert_eq!(branch(command).as_deref(), Ok(expected), "{command}");
    }
    for command in [
        "git push",
        "git push origin",
        "git push upstream dev",
        "git push origin dev main",
        "git push -f origin dev",
        "git push --force-with-lease origin dev",
        "git push origin +dev",
        "git push origin :dev",
        "git push origin dev:other",
        "git push origin HEAD",
        "git push origin ORIG_HEAD:dev",
        "git push --tags origin dev",
        "git push --follow-tags origin dev",
        "git push --no-verify origin dev",
        "git push -o ci.skip origin dev",
        "git push origin 'refs/heads/*'",
        "git push origin ../dev",
        "git push origin -dev",
        "git -c core.sshCommand=evil push origin dev",
        "git -C ../other push origin dev",
        "/usr/bin/git push origin dev",
        "git pull origin dev",
    ] {
        assert_eq!(branch(command), Err(MUTABLE_LAUNCHER), "{command}");
    }
}

#[test]
fn a_push_without_the_agents_stamped_environment_is_not_bound() {
    for command in [
        "git push origin dev && rm -rf build",
        "git push origin dev | tee log",
    ] {
        assert_eq!(
            push_state(command, "/", None),
            Err(COMPOUND_COMMAND),
            "{command}"
        );
    }
    for command in ["git push origin $(whoami)", "git push origin dev # note"] {
        assert_eq!(
            push_state(command, "/", None),
            Err(MUTABLE_LAUNCHER),
            "{command}"
        );
    }
    assert_eq!(
        push_state("git push origin dev", "/", None),
        Err(UNPROVEN_LAUNCH)
    );
    let malformed = json!({"path": 7});
    assert_eq!(
        push_state("git push origin dev", "/", Some(&malformed)),
        Err(UNPROVEN_LAUNCH)
    );
}

#[test]
fn an_agent_environment_that_reroutes_or_loads_code_is_not_bound() {
    let home = std::env::temp_dir();
    let home = home.to_string_lossy();
    for name in [
        "SSH_SK_PROVIDER",
        "SSH_ASKPASS",
        "GIT_SSH_COMMAND",
        "GIT_ASKPASS",
        "GIT_CONFIG_GLOBAL",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FRAMEWORK_PATH",
    ] {
        let environment = json!({
            "path": "/usr/bin:/bin",
            "home": home,
            "environment_names": ["HOME", "PATH", name],
            "environment_digest": "a".repeat(64),
        });
        assert_eq!(
            push_state("git push origin dev", &home, Some(&environment)),
            Err(GIT_HELPER_CONFIG),
            "{name}"
        );
    }
}
