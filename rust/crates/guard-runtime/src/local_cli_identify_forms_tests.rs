use super::names_shell;

#[test]
fn a_shebang_runs_a_shell_directly_or_through_env() {
    for line in [
        "/bin/sh",
        "/bin/bash -e",
        "/usr/bin/env bash",
        "/usr/bin/env -S zsh -f",
    ] {
        assert!(names_shell(line), "{line}");
    }
    for line in [
        "/usr/bin/python3",
        "/usr/bin/env python3",
        "/usr/bin/env",
        "/usr/bin/env A=1",
    ] {
        assert!(!names_shell(line), "{line}");
    }
}

#[cfg(unix)]
mod launched {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use guard_contracts::UnlistedCliV1;

    use super::super::super::{identify, Request};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "lci-forms-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(path.join("bin")).unwrap();
            Self(path.canonicalize().unwrap())
        }

        fn tool(&self, name: &str, body: &str, mode: u32) -> String {
            let path = self.0.join("bin").join(name);
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path.to_str().unwrap().to_owned()
        }

        fn launched(&self, command: &str) -> Vec<UnlistedCliV1> {
            let home = self.0.to_str().unwrap();
            let env = BTreeMap::from([("PATH".to_owned(), "/usr/bin:/bin".to_owned())]);
            identify(&Request {
                command_text: command,
                cwd: home,
                home_dir: Some(home),
                user_home: home,
                compound: false,
                env: &env,
                budget_ms: 5_000,
            })
            .unwrap()
        }

        fn one(&self, command: &str) -> UnlistedCliV1 {
            let mut found = self.launched(command);
            assert_eq!(found.len(), 1, "{command}");
            found.remove(0)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn same(left: &UnlistedCliV1, right: &UnlistedCliV1) -> bool {
        left.cli_id == right.cli_id && left.identity_hash == right.identity_hash
    }

    const SHELL_TOOL: &str = "#!/bin/sh\necho ready\n";

    #[test]
    fn a_shell_running_an_executable_shell_script_names_its_direct_launch() {
        let scratch = Scratch::new();
        let path = scratch.tool("relayctl", SHELL_TOOL, 0o755);
        let direct = scratch.one(&format!("{path} status"));
        assert_eq!(direct.kind, "executable");
        assert_eq!(direct.name, "relayctl");
        for shell in ["bash", "sh"] {
            let run = scratch.one(&format!("{shell} {path} status"));
            assert!(same(&run, &direct), "{shell}");
            assert_eq!(run.name, "relayctl");
        }
    }

    #[test]
    fn a_shell_run_selects_the_subcommand_a_direct_launch_selects() {
        let scratch = Scratch::new();
        let path = scratch.tool("relayctl", SHELL_TOOL, 0o755);
        let home = scratch.0.to_str().unwrap();
        let tokens = |command: &str| {
            let found = scratch.one(command);
            crate::local_cli_hook_op::invocation_command_tokens(
                command,
                home,
                Some(home),
                &found.name,
                &found.kind,
                None,
            )
        };
        let direct = tokens(&format!("{path} lane drain --force"));
        assert_eq!(direct, ["lane", "drain"]);
        for shell in ["bash", "sh"] {
            assert_eq!(
                tokens(&format!("{shell} {path} lane drain --force")),
                direct
            );
        }
    }

    #[test]
    fn a_shell_option_before_the_script_names_no_direct_launch() {
        let scratch = Scratch::new();
        let path = scratch.tool("relayctl", SHELL_TOOL, 0o755);
        let found = scratch.launched(&format!("bash -e {path} lane drain"));
        assert!(
            found.iter().all(|cli| cli.kind != "executable"),
            "{found:?}"
        );
    }

    #[test]
    fn a_changed_script_names_a_new_identity_in_every_form() {
        let scratch = Scratch::new();
        let path = scratch.tool("relayctl", SHELL_TOOL, 0o755);
        let before = scratch.one(&format!("bash {path} status"));
        std::fs::write(&path, "#!/bin/sh\necho changed\n").unwrap();
        let after = scratch.one(&format!("bash {path} status"));
        assert_eq!(after.cli_id, before.cli_id);
        assert_ne!(after.identity_hash, before.identity_hash);
        assert!(same(&after, &scratch.one(&format!("{path} status"))));
    }

    #[test]
    fn a_script_no_direct_launch_runs_keeps_its_script_identity() {
        let scratch = Scratch::new();
        let unexecutable = scratch.tool("relayctl", SHELL_TOOL, 0o644);
        assert_eq!(scratch.one(&format!("bash {unexecutable}")).kind, "script");
        let python = scratch.tool("pyctl", "#!/usr/bin/env python3\nprint(1)\n", 0o755);
        let run = scratch.one(&format!("bash {python}"));
        assert_eq!(run.kind, "script");
        assert!(!same(&run, &scratch.one(&python)));
        let bare = scratch.tool("barectl", "echo ready\n", 0o755);
        assert_eq!(scratch.one(&format!("sh {bare}")).kind, "script");
    }

    #[test]
    fn a_pipeline_that_only_filters_output_launches_its_first_stage() {
        let scratch = Scratch::new();
        let path = scratch.tool("relayctl", SHELL_TOOL, 0o755);
        let direct = scratch.one(&format!("{path} status"));
        for command in [
            format!("{path} status 2>&1 | tail -15"),
            format!("bash {path} status 2>&1 | tail -15"),
            format!("{path} status | head -n 5 | wc -l"),
        ] {
            assert!(same(&scratch.one(&command), &direct), "{command}");
        }
    }

    #[test]
    fn a_pipeline_stage_that_can_act_names_no_launch() {
        let scratch = Scratch::new();
        let path = scratch.tool("relayctl", SHELL_TOOL, 0o755);
        let out = scratch.0.join("out.txt");
        let out = out.to_str().unwrap();
        for command in [
            format!("{path} status | sh"),
            format!("{path} status | tee {out}"),
            format!("{path} status | tail -5 > {out}"),
            format!("{path} status | tail {out}"),
            format!("{path} status; tail -5"),
            format!("{path} status && tail -5"),
            format!("echo status | {path}"),
        ] {
            assert!(scratch.launched(&command).is_empty(), "{command}");
        }
    }
}
