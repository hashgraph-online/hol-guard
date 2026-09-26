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
        "gh pr merge 1 --squash",
        "gh pr view 6374 --json url,state",
        "gh pr view --web 1",
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
        "cat README.md Cargo.toml",
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
    for command in [
            "rg --pre /opt/guard-test/payload authority src",
            "rg --hostname-bin=/opt/guard-test/payload --hyperlink-format='file://{host}{path}' TOKEN src",
            "rg --hidden authority .",
            "rg -uuu authority .",
            "rg -L authority .",
            "rg --no-ignore-files authority .",
            "rg --glob '*.env' TOKEN .",
            "rg --glob '*.{env,ts}' TOKEN .",
            "rg --glob 'nested/*.env' TOKEN .",
            "rg --glob 'nested/[.]env' TOKEN .",
            r"rg --glob 'nested/[\.]env' TOKEN .",
            "rg --glob 'nested/{safe,.env}' TOKEN .",
            "rg TOKEN .env.local",
            "rg -e '.env.local' src",
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
            "FOO=bar git status --short",
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
fn denies_uncertain_or_networked_commands() {
    for command in [
        "echo $(whoami)",
        "pwd && rm -rf /",
        "python -c 'print(1)'",
        "git push origin main",
        "PATH=/tmp:$PATH ls",
    ] {
        let decision = evaluate_pre_tool(&request(command)).unwrap();
        assert_eq!(decision.decision, "deny", "{command}");
        assert_ne!(decision.minimum_action, "allow", "{command}");
    }
}
