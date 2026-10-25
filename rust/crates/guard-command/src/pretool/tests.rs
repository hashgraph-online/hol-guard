use super::*;

fn request(command: &str) -> CommandModelRequestV1 {
    CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }
}

#[test]
fn bounded_byte_inspection_preserves_secret_and_pipeline_floors() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    let root = root.to_str().unwrap();
    for command in [
        "od -c src/lib.rs",
        "wc -c src/lib.rs && od -c src/lib.rs | tail -2",
        "cat src/lib.rs | od -An -tx1",
        "cat src/lib.rs | od -c -",
    ] {
        let decision =
            evaluate_pre_tool_with_context(&request(command), Some(root), Some(root)).unwrap();
        assert_eq!(decision.minimum_action, "allow", "{command}");
    }
    for command in [
        "od -c .env",
        "od -c ~/.ssh/id_rsa",
        "od -c /etc/shadow",
        "cat .env | od -c",
        "od -c src/lib.rs; rm -rf src",
        "od -c src/lib.rs > .env",
        "od -c src/lib.rs .env",
        "od -c",
        "od --unknown src/lib.rs",
        "od -c $(echo src/lib.rs)",
    ] {
        let decision = evaluate_pre_tool_with_context(&request(command), Some(root), Some(root));
        assert!(
            decision.is_err() || decision.unwrap().minimum_action != "allow",
            "{command}"
        );
    }
    assert_ne!(
        evaluate_pre_tool(&request("od -c src/lib.rs"))
            .unwrap()
            .minimum_action,
        "allow"
    );
}

#[test]
fn bounded_find_listings_do_not_admit_actions_or_sensitive_targets() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    let root = root.to_str().unwrap();
    for command in [
        "find src -type f",
        "find -P src -maxdepth 3 -type f",
        "find src -type f | head -5",
    ] {
        let decision =
            evaluate_pre_tool_with_context(&request(command), Some(root), Some(root)).unwrap();
        assert_eq!(decision.minimum_action, "allow", "{command}");
    }
    for command in [
        "find .env -type f",
        "find ~/.ssh -type f",
        "find -L src -type f",
        "find src -type f -delete",
        "find src -type f -exec sh {} ;",
        "find src -type f -fprint output.txt",
        "find src .env -type f",
        "find src -maxdepth 999 -type f",
        "find src -type f && cat .env",
    ] {
        let decision = evaluate_pre_tool_with_context(&request(command), Some(root), Some(root));
        assert!(
            decision.is_err() || decision.unwrap().minimum_action != "allow",
            "{command}"
        );
    }
    assert_ne!(
        evaluate_pre_tool(&request("find src -type f"))
            .unwrap()
            .minimum_action,
        "allow"
    );
}

/// `[[ -f NAME ]]` is read as the `[ -f NAME ]` it asks: inside `[[ ]]` the
/// shell splits no word and expands no glob, so the modeled form stands for
/// at least the work the command does. Only a closed pair is read that way;
/// an unclosed `[[`, a pair `&&` has already split, and an unmodeled
/// predicate each keep their review.
#[test]
fn bounded_file_predicates_preserve_compound_path_and_command_risks() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    let root = root.to_str().unwrap();
    for command in [
        "test -f src/lib.rs && cat src/lib.rs",
        "test -d src && ls src",
        "test -e src/lib.rs; echo done",
        "test -r src/lib.rs && head -1 src/lib.rs",
        "test -x src && echo searchable || echo closed",
        "test -s src/lib.rs && echo non-empty",
        "[ -f src/lib.rs ] && echo present || echo missing",
        "[[ -f src/lib.rs ]] && echo present || echo missing",
        "[[ -d src ]] && ls src",
        "if [[ -f src/lib.rs ]]; then cat src/lib.rs; fi",
    ] {
        let decision =
            evaluate_pre_tool_with_context(&request(command), Some(root), Some(root)).unwrap();
        assert_eq!(decision.minimum_action, "allow", "{command}");
        assert_ne!(
            evaluate_pre_tool(&request(command)).unwrap().minimum_action,
            "allow"
        );
    }
    for command in [
        "test -f .env && cat .env",
        "test -e ~/.ssh/id_rsa",
        "test -f src/lib.rs && rm -rf src",
        "test -f src/lib.rs -o -f .env",
        "test -f $(echo src/lib.rs)",
        "test -x ~/.ssh/id_rsa",
        "test -s .env && echo set",
        "test -w src/lib.rs",
        "[ -f .env ] && echo set",
        "[ -f src/lib.rs",
        "[[ -f .env ]] && echo set",
        "[[ -f src/lib.rs",
        "[[ -f src/lib.rs && -f .env ]]",
        "[[ -w src/lib.rs ]]",
    ] {
        let decision = evaluate_pre_tool_with_context(&request(command), Some(root), Some(root));
        assert!(
            decision.is_err() || decision.unwrap().minimum_action != "allow",
            "{command}"
        );
    }
}

#[test]
fn permits_only_standalone_plain_directory_changes() {
    assert!(!safe_directory_target(r"~/.ss\h"));
    for command in [
        "cd ~/CascadeProjects/project",
        "cd ./project",
        "cd /opt/project",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.minimum_action, "allow", "{command}");
    }
    for command in [
        "cd $(touch marker)",
        "cd `touch marker`",
        "cd ~/project && python script.py",
        "cd /opt/project | cat file.txt",
        "cd ~/.ssh",
        "cd /opt/user/.ssh",
        "cd ~/.s*",
        "cd .ssh*",
        "cd ./project?",
        "cd ./[project]",
        "cd -",
        "cd ~+",
        "cd ~-",
        "cd ~+/project",
        "cd ~-/project",
        "cd ~0",
        "cd ~1",
        "cd ~0/project",
        "cd ~12/project",
        "cd ~+1/project",
        "cd ~-1/project",
    ] {
        let result = evaluate_pre_tool(&request(command));
        assert!(
            result.is_err() || result.unwrap().minimum_action != "allow",
            "{command}"
        );
    }
}

#[test]
fn read_only_github_predecessor_counts_as_benign_for_git_context() {
    let model = parse_command(&request(
        "gh api repos/owner/repo/compare/base...main; git status --short",
    ))
    .unwrap();
    assert_eq!(
        benign_command_segments(
            &model,
            PathContext {
                home_dir: Some("/tmp"),
                cwd: Some("/tmp"),
                cdpath_unset: false,
                rustup_override_absent: false,
                npm_config_inert: false,
                pip_config_inert: false,
                shell_home_matches: false,
                ripgrep_config_absent: false,
                psql_environment: Default::default(),
                creates_nothing: false,
            },
        ),
        vec![0, 1]
    );
}

#[cfg(unix)]
#[test]
fn stderr_null_sink_preserves_each_compound_command_risk() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    let root = root.to_str().unwrap();
    for command in [
        "ls -la src 2>/dev/null",
        "ls -la; echo ---; ls -la src 2>/dev/null; echo done",
        "grep -n use src/lib.rs 2>/dev/null | head -1",
    ] {
        let decision =
            evaluate_pre_tool_with_context(&request(command), Some(root), Some(root)).unwrap();
        assert_eq!(
            decision.minimum_action, "allow",
            "{command}: {}",
            decision.reason_code
        );
    }
    for command in [
        "cat .env 2>/dev/null",
        "ls src 2>/dev/null; rm -rf src",
        "cat src/lib.rs 2> .env",
        "ls src 2>/dev/null; cat .env",
    ] {
        let decision =
            evaluate_pre_tool_with_context(&request(command), Some(root), Some(root)).unwrap();
        assert_ne!(decision.minimum_action, "allow", "{command}");
    }
}

#[test]
fn encoded_github_reads_remain_benign_in_compounds() {
    for command in [
        "gh api 'repos/owner/repo/contents/app/%28group%29/file.ts?ref=main'",
        "echo ready && gh api 'repos/owner/repo/commits?path=app/%28group%29/file.ts' --jq '.[].sha' | head -1",
    ] {
        let result = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(result.minimum_action, "allow", "{command}: {}", result.reason_code);
    }
    for command in [
        "gh api 'repos/owner/repo/contents/app/%28group%29/file.ts'; cat .env",
        "gh api -X DELETE 'repos/owner/repo/contents/app/%28group%29/file.ts'",
        "gh api 'repos/owner/repo/contents/app/%28group%29/file.ts' && rm -rf src",
    ] {
        let result = evaluate_pre_tool(&request(command)).unwrap();
        assert_ne!(result.minimum_action, "allow", "{command}");
    }
}

#[test]
fn git_c_inspections_require_verified_repository_scope() {
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let repository = repository.to_str().unwrap();
    let allowed = evaluate_pre_tool_with_context(
        &request("git -C . status --short"),
        Some(repository),
        Some(repository),
    )
    .unwrap();
    assert_eq!(allowed.minimum_action, "allow");
    assert!(allowed.explicitly_benign);

    for (command, home, cwd) in [
        ("git -C . status --short", None, None),
        (
            "git -C rust status --short",
            Some(repository),
            Some(repository),
        ),
        (
            "git -C .. status --short",
            Some(repository),
            Some(repository),
        ),
    ] {
        let decision = evaluate_pre_tool_with_context(&request(command), home, cwd).unwrap();
        if command == "git -C rust status --short" {
            assert_eq!(decision.minimum_action, "allow", "{command}");
            assert!(decision.explicitly_benign, "{command}");
        } else {
            assert_ne!(decision.minimum_action, "allow", "{command}");
            assert!(!decision.explicitly_benign, "{command}");
        }
    }
}

#[test]
fn git_c_rejects_external_gitfile_pointers() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/gitfile-pointer-fixtures");
    std::fs::create_dir_all(&base).unwrap();
    let nonce = crate::unique_nanos::unique_nanos();
    let fixture = base.join(format!("fixture-{}-{nonce}", std::process::id()));
    let workspace = fixture.join("workspace");
    let external = fixture.join("external-admin");
    std::fs::create_dir_all(workspace.join("nested")).unwrap();
    std::fs::create_dir_all(&external).unwrap();
    std::fs::write(
        workspace.join(".git"),
        format!("gitdir: {}\n", external.display()),
    )
    .unwrap();
    let workspace = workspace.canonicalize().unwrap();
    let workspace = workspace.to_str().unwrap();
    let decision = evaluate_pre_tool_with_context(
        &request("git -C nested status --short"),
        Some(workspace),
        Some(workspace),
    )
    .unwrap();
    assert_ne!(decision.minimum_action, "allow");
    let _ = std::fs::remove_dir_all(fixture);
}

#[test]
fn git_c_rejects_forged_external_linked_worktree_metadata() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/gitfile-pointer-fixtures");
    std::fs::create_dir_all(&base).unwrap();
    let nonce = crate::unique_nanos::unique_nanos();
    let fixture = base.join(format!("linked-fixture-{}-{nonce}", std::process::id()));
    let workspace = fixture.join("workspace");
    let common = fixture.join("external-common/.git");
    let admin = common.join("worktrees/workspace");
    std::fs::create_dir_all(workspace.join("nested")).unwrap();
    std::fs::create_dir_all(&admin).unwrap();
    std::fs::write(workspace.join("wrong.git"), "forged\n").unwrap();
    std::fs::write(
        workspace.join(".git"),
        "gitdir: ../external-common/.git/worktrees/workspace\n",
    )
    .unwrap();
    std::fs::write(admin.join("commondir"), "../..\n").unwrap();
    std::fs::write(
        admin.join("gitdir"),
        format!("{}\n", workspace.join("wrong.git").display()),
    )
    .unwrap();
    let workspace = workspace.canonicalize().unwrap();
    let decision = evaluate_pre_tool_with_context(
        &request("git -C nested status --short"),
        workspace.to_str(),
        workspace.to_str(),
    )
    .unwrap();
    assert_ne!(decision.minimum_action, "allow");
    let _ = std::fs::remove_dir_all(fixture);
}

#[test]
fn blocks_destructive_and_device_commands() {
    for command in [
        "rm -rf /",
        "rm -rf -- /",
        "shred ~/.ssh/id_ed25519",
        "dd if=/dev/zero of=/dev/sda",
        "mkfs.ext4 /dev/sda1",
        "shutdown -h now",
        "reboot",
        "wipefs -a /dev/sda",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.decision, "deny", "{command}");
        assert_eq!(decision.minimum_action, "block", "{command}");
    }
}

#[test]
fn reviews_home_relative_secret_paths() {
    let decision = evaluate_pre_tool(&request("cat ~/.npmrc")).unwrap();
    assert_eq!(decision.decision, "deny");
    assert_eq!(decision.minimum_action, "review");
    assert_eq!(decision.reason_code, "native_sensitive_access_review");
}

#[test]
fn reviews_dotenv_family_shell_reads() {
    for command in [
        "cat .env",
        "cat .env.synthetic",
        "cat /workspace/.env.local",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.decision, "deny", "{command}");
        assert_eq!(decision.minimum_action, "review", "{command}");
        assert_eq!(
            decision.reason_code, "native_sensitive_access_review",
            "{command}"
        );
    }
}

#[test]
fn windows_aliases_of_secret_paths_get_the_plain_path_decision() {
    // Win32 drops trailing dots and spaces from each name and reads
    // `name::$DATA` as the file's default stream.
    for (alias, plain) in [
        ("cat '.env::$DATA'", "cat .env"),
        ("cat '.env::$DATA.'", "cat .env"),
        ("cat '.ENV. '", "cat .env"),
        ("cat ~/.npmrc.", "cat ~/.npmrc"),
        ("cat ~/.ssh./id_rsa.", "cat ~/.ssh/id_rsa"),
        ("cat '.aws\\credentials::$DATA'", "cat .aws/credentials"),
        ("cat notes.md.", "cat notes.md"),
    ] {
        let alias_decision = evaluate_pre_tool(&request(alias)).unwrap();
        let plain_decision = evaluate_pre_tool(&request(plain)).unwrap();
        assert_eq!(
            (
                alias_decision.decision,
                alias_decision.minimum_action,
                alias_decision.reason_code
            ),
            (
                plain_decision.decision,
                plain_decision.minimum_action,
                plain_decision.reason_code
            ),
            "{alias}"
        );
    }
}

#[test]
fn allows_bounded_exact_commands() {
    for command in [
        "pwd",
        "whoami",
        "uname -a",
        "git status --short",
        "git status --short --branch",
        "git remote -v",
        "git remote --verbose",
        "git remote -v --",
        "git remote --verbose --",
        "gh auth status",
        "gh auth status --help",
        "gh auth status -h",
        "git remote -v && gh auth status",
        "git rev-parse --show-toplevel",
        "git diff --no-ext-diff --no-textconv --check",
        "rg -n authority src",
        "rg -g*.ts authority src",
        "rg --glob '*.{ts,tsx}' authority src",
        "rg --files -g '!**/.git/**'",
        "rg --glob='!*.lock' authority src",
        "rg --line-number --color=never authority src",
        "grep -n authority README.md",
        "grep --line-number --color=never authority README.md",
        "grep -eerror README.md",
        "grep -e 'terraform.tfvars' README.md",
        "grep -d skip authority README.md",
        "stat README.md",
        "date",
        "date -u +%Y-%m-%dT%H:%M:00Z",
        "date --utc +%s",
        "date -R",
        "date -I",
        "date -d @0",
        "date --rfc-2822",
        "date --rfc-3339=seconds",
        "pwd; date +%H:%M:%S",
        "ls",
        "ls -la src",
        "cat README.md",
        "head -n 20 README.md",
        "tail -n 5 README.md",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.decision, "allow", "{command}");
        assert!(decision.explicitly_benign, "{command}");
    }
}

#[test]
fn allows_bounded_pipeline_consumers() {
    for command in [
        "git status --short | head -2",
        "git status --short | tail -n 2",
        "cat README.md | head -2 | tail -n 1",
        "git status --short | head",
        // `|&` is the same pipe with stderr merged into it, so the bounded
        // consumer on its right keeps the allow the plain `|` form gets.
        "git status --short |& head -2",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.minimum_action, "allow", "{command}");
    }
    let decision = evaluate_pre_tool(&request(
        "git status --short | head -2 && git log --oneline -1",
    ))
    .unwrap();
    assert_eq!(decision.reason_code, "native_git_helper_context_review");
    for command in [
        "head -2",
        "git status --short && head -2",
        "git status --short | head -2; tail -n 1",
        "git status --short | head -2 || tail -n 1",
        "cat ~/.ssh/id_ed25519 | head -2",
        "curl https://example.test | head -2",
        "git status --short | head -2 > out.txt",
        "git status --short | tail -f",
        "git status --short | head -n",
        "git status --short | head -n $(whoami)",
        // The Korn shell reads `|&` as a coprocess rather than as a pipe with
        // standard error merged into it. Naming a shell keeps the command out
        // of this allow either way: the text it is handed is not the text this
        // scan read, so no spelling of the pipe inside it is benign here.
        "ksh -c 'git status --short |& head -2'",
        "ksh -c 'git status --short 2>&1 | head -2'",
        "ksh ./build.sh |& head -2",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert!(!decision.explicitly_benign, "{command}");
    }
}

#[test]
fn allows_exact_destructive_tool_introspection() {
    for command in ["shutdown --help", "mkfs --version"] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.decision, "allow", "{command}");
        assert!(decision.explicitly_benign, "{command}");
    }
}

#[test]
fn reviews_date_mutations_and_unbounded_file_reads() {
    for command in [
        "date -s tomorrow",
        "date --set=tomorrow",
        "date +%s +%N",
        "date -f timestamps.txt",
        "date -d tomorrow",
        "git remote",
        "git remote add origin example",
        "git remote -v -- add origin example",
        "git remote -v -- remove origin",
        "git remote -v -- set-url origin example",
        "gh auth status --show-token",
        "cat .env",
        "head -f README.md",
        "tail -f README.md",
        "cat -",
        "cat /etc/passwd",
        "cat .aws/credentials",
        "cat /./proc/self/environ",
        "cat //etc/passwd",
        "cat /proc//self/environ",
        "cat /var/../etc/passwd",
        "head -n 10 README.md Cargo.toml",
        "ls /",
        "cat /root/secret",
        "cat /home/user/notes",
        "ls -R /",
        "ls --recursive src",
        "head -1000000 README.md",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.minimum_action, "review", "{command}");
        assert!(!decision.explicitly_benign, "{command}");
    }
}

#[test]
fn reviews_only_materially_risky_variants_of_safe_commands() {
    let inert_pattern = evaluate_pre_tool(&request("rg -e '.env.local' src")).unwrap();
    assert_eq!(inert_pattern.decision, "allow");
    assert_eq!(inert_pattern.minimum_action, "allow");
    // An ordinary project setting in front of a proven read is a value that
    // read takes for itself. Every name that could steer lookup, loading,
    // configuration, a home, a credential, the trust anchor or an endpoint
    // keeps its review, and the cases below still cover those families.
    let ordinary_setting = evaluate_pre_tool(&request("FOO=bar git status --short")).unwrap();
    assert_eq!(ordinary_setting.decision, "allow");
    for command in [
            "rg --pre /opt/guard-test/payload authority src",
            "rg --hostname-bin=/opt/guard-test/payload --hyperlink-format='file://{host}{path}' TOKEN src",
            "rg --hidden authority .",
            "rg -uuu authority .",
            "rg -L authority .",
            "rg --no-ignore-files authority .",
            "rg --glob '*.env' TOKEN .",
            "rg --glob '!*.md' --glob '*.env' TOKEN .",
            "rg --glob '*.{env,ts}' TOKEN .",
            "rg --glob 'nested/*.env' TOKEN .",
            "rg --glob 'nested/[.]env' TOKEN .",
            r"rg --glob 'nested/[\.]env' TOKEN .",
            "rg --glob 'nested/{safe,.env}' TOKEN .",
            "rg TOKEN .env.local",
            "grep -r password .",
            "rg id_rsa /home",
            "rg --glob 'nested/[.]env.local' TOKEN .",
            "rg --glob 'nested/[.]env.production' TOKEN .",
            "rg --glob 'nested/[.]e[n]v.production' TOKEN .",
            "rg --glob 'nested/[.]e*v.production' TOKEN .",
            "rg --glob 'my-private-[k]ey-prod.pem' TOKEN .",
            "rg --glob 'my-private-[ak]ey-prod.pem' TOKEN .",
            "rg --glob 'my-pr[i]vate-[k]ey-prod.pem' TOKEN .",
            "rg --type-add 'secret:.env' -tsecret TOKEN .",
            "rg TOKEN .aws/config",
            "rg TOKEN terraform.tfvars",
            "rg TOKEN wallet.key",
            "rg TOKEN .gnupg/private-keys-v1.d/key",
            "rg authority .env",
            "grep authority .npmrc",
            "grep TOKEN .*",
            "grep TOKEN '.[a-z]*'",
            "grep TOKEN nested/.*",
            "grep -R authority .",
            "grep -d recurse TOKEN .",
            "grep --directories=recurse TOKEN .",
            "grep --recursiv TOKEN .",
            "grep --direct=recurse TOKEN .",
            "rg --hidd TOKEN .",
            "rg --globx '*.ts' TOKEN .",
            "/opt/guard-test/rg authority src",
            "GIT_EXTERNAL_DIFF=/opt/guard-test/payload git diff --ext-diff README.md",
            "git diff --output=/opt/guard-test/diff README.md",
            "git log -1 --output=/opt/guard-test/log",
            "git diff --check",
            "git log -1",
            "git show HEAD",
            "git show HEAD:.env",
            "git show HEAD:.git/config",
        ] {
            let decision = evaluate_pre_tool(&request(command)).unwrap();
            assert_eq!(decision.decision, "deny", "{command}");
            assert_eq!(decision.minimum_action, "review", "{command}");
            assert!(!decision.explicitly_benign, "{command}");
        }
}

#[test]
fn defers_only_exact_safe_git_helper_context() {
    let contextual = evaluate_pre_tool(&request("git diff --check")).unwrap();
    assert_eq!(contextual.reason_code, "native_git_helper_context_review");

    let unsafe_output =
        evaluate_pre_tool(&request("git diff --output=/tmp/diff README.md")).unwrap();
    assert_eq!(unsafe_output.reason_code, "native_command_review_required");

    let option_shaped_paths =
        evaluate_pre_tool(&request("git diff -- --no-ext-diff --no-textconv")).unwrap();
    assert_eq!(
        option_shaped_paths.reason_code,
        "native_git_helper_context_review"
    );
}

#[test]
fn denies_uncertain_or_networked_commands_but_allows_proven_constant_expression() {
    for (command, permitted) in [
        ("echo $(whoami)", false),
        ("pwd && rm -rf /", false),
        ("python -c 'print(1)'", true),
        ("git push origin main", false),
        ("PATH=/tmp:$PATH ls", false),
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.decision == "allow", permitted, "{command}");
        assert_eq!(decision.minimum_action == "allow", permitted, "{command}");
    }
}

#[test]
fn guard_control_floors_block_natively_instead_of_queueing_review() {
    for command in [
        "hol-guard uninstall",
        "hol-guard uninstall --all",
        "hol-guard hooks remove --all",
        "hol-guard hooks remove",
        "/usr/local/bin/hol-guard hooks remove --all",
        "HOL-GUARD Hooks Remove --all",
        "hol-guard policy disable",
        "hol-guard capability consume token",
        "hol-guard clear --all",
        "sudo hol-guard hooks remove --all",
        "echo ok && hol-guard hooks remove --all",
        "echo x | xargs hol-guard uninstall",
        "find . -exec hol-guard hooks remove --all \\;",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.minimum_action, "block", "{command}");
        assert_eq!(
            decision.reason_code, "native_guard_self_protection",
            "{command}"
        );
        assert!(!decision.explicitly_benign, "{command}");
    }
}

#[test]
fn guard_control_help_and_other_subcommands_keep_review() {
    for command in [
        "hol-guard hooks remove --help",
        "hol-guard uninstall --help",
        "hol-guard hooks list",
        "hol-guard repair",
        "echo x | xargs echo",
        "find . -name '*.py' -exec echo {} \\;",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_ne!(decision.minimum_action, "block", "{command}");
        assert_ne!(
            decision.reason_code, "native_guard_self_protection",
            "{command}"
        );
    }
}

#[test]
fn magic_pathspecs_are_screened_by_the_path_they_name() {
    for selecting in [":(top).en*", ":(top,glob).en*", ":/!.en?", ":(top).env"] {
        assert!(sensitive_read_path_argument(selecting), "{selecting}");
    }
    for ordinary in [":(top)src/*.ts", ":!readme.md", ":(exclude)src"] {
        assert!(!sensitive_read_path_argument(ordinary), "{ordinary}");
    }
}

#[test]
fn secret_selecting_globs_are_a_fixed_floor() {
    let model = |command: &str| {
        crate::parse_command(
            &serde_json::from_value(serde_json::json!({"command": command})).unwrap(),
        )
        .unwrap()
    };
    for command in [
        "git diff --no-index .en? README.md",
        "git log -p -1 -- ':(top).en*'",
        "dd if=.en{v..v} of=copy",
        "dd if=.e{n..n}{v..v} of=copy",
        "dd if={.env,x} of=copy",
        // An `=` or whitespace inside a pattern can still match `.env`.
        "git diff --no-index [=.]env README.md",
        "git diff --no-index {=,.}env README.md",
        "git log -p -1 -- '[ .]env'",
        "git log -p -1 -- '{ ,.}env'",
        "git log -p -1 -- 'my dir/.en?'",
        // A leading `]`, a backslash or a `[:name:]` keeps the class whole.
        "git log -p -1 -- '[] .]env'",
        "git log -p -1 -- '[\\] .]env'",
        "git log -p -1 -- '[!]a]env'",
        "git log -p -1 -- '[[:space:].]env'",
        "git log -p -1 -- '[[=.=]]env'",
        // A brace value is screened per alternative, whatever else it holds.
        "dd if={safe:dummy,.env} of=copy",
        "dd if={x\\\"y,.env} of=copy",
        // An unterminated quote leaves no proven segment to screen.
        "dd if='{x,.env} of=copy",
        // A `/` makes the word a path, whatever its first component holds.
        "git log -p -1 -- 'x=y/../.en*'",
        "git diff --no-index a=b/{.env,x} README.md",
    ] {
        assert!(fixed_command_floor(&model(command)), "{command}");
    }
    for command in [
        "git log -p -1 -- 'src/*.ts'",
        "git commit -m 'ignore *.env files'",
        "gh api graphql -f query='mutation{resolveReviewThread(input:{threadId:\"x\"}){thread{id,isResolved}}}'",
        "gh api graphql -f query='{viewer{login}}'",
        "gh pr comment 1 --body 'see *.env and .en{v..v}'",
        "dd if=out.* of=copy",
        "gh pr comment 1 --body 'fix the [.]env loader'",
        "gh api graphql -f query='query { viewer { login } }'",
        "gh pr comment 1 --body 'use arr[] and fix ]'",
        "gh api repos/o/r/issues -f 'labels[]=bug'",
        "dd if=out/*.ts of=copy",
        "git log -p -1 -- '[[:digit:]].ts'",
    ] {
        assert!(!fixed_command_floor(&model(command)), "{command}");
    }
}
