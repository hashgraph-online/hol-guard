use super::*;

fn input(workspace: &str) -> Input {
    Input {
        profile_version: WORKSPACE_CONTAINED_PROFILE.into(),
        workspace: PathBuf::from(workspace),
        cwd: PathBuf::from(workspace),
        private_root: PathBuf::from("/private/tmp/guard-private"),
        ..Input::default()
    }
}

fn git_regex(workspace: &str) -> Regex {
    Regex::new(&workspace_profile::git_exec_pattern(Path::new(workspace)).unwrap()).unwrap()
}

#[test]
fn git_execution_config_is_denied_at_any_depth_and_case() {
    let re = git_regex("/w/proj");
    for denied in [
        "/w/proj/.git",
        "/w/proj/.GIT/Config",
        "/w/proj/.git/config.lock",
        "/w/proj/.git/hooks",
        "/w/proj/a/b/.git/hooks/pre-commit",
        "/w/proj/sub/.git",
        "/w/proj/.git/objects/info/alternates",
        "/w/proj/.git/modules/x/config",
    ] {
        assert!(re.is_match(denied), "{denied}");
    }
    for allowed in [
        "/w/proj/.github/x",
        "/w/proj/src/git/config",
        "/w/proj/.git/index",
        "/w/proj/.git/objects/ab/cdef",
        "/w/proj/.git/refs/heads/main",
        "/w/other/.git/config",
    ] {
        assert!(!re.is_match(allowed), "{allowed}");
    }
}

#[test]
fn literals_with_regex_specials_are_escaped_and_backslashes_rejected() {
    let re = git_regex("/w/a+b(c)");
    assert!(re.is_match("/w/a+b(c)/.git/config"));
    assert!(!re.is_match("/w/aab(c)/.git/config"));
    assert!(workspace_profile::git_exec_pattern(Path::new("/w/a\\b")).is_err());
    assert!(workspace_profile::git_exec_pattern(Path::new("/w/a^b")).is_err());
    assert!(workspace_profile::protected_patterns(Path::new("/w/a^b")).is_err());
}

#[test]
fn protected_paths_are_denied_for_writes() {
    let patterns = workspace_profile::protected_patterns(Path::new("/w/proj")).unwrap();
    let denied = |path: &str| {
        patterns
            .iter()
            .any(|p| Regex::new(p).unwrap().is_match(path))
    };
    assert!(denied("/w/proj/.claude/settings.json"));
    assert!(denied("/w/proj/pkg/.codex/x"));
    assert!(denied("/w/proj/CLAUDE.md"));
    assert!(denied("/w/proj/.mcp.json"));
    assert!(denied("/w/proj/.github/workflows/ci.yml"));
    assert!(!denied("/w/proj/src/main.rs"));
}

#[test]
fn harness_configuration_is_denied_for_writes_at_any_depth() {
    let patterns = workspace_profile::protected_patterns(Path::new("/w/proj")).unwrap();
    let denied = |path: &str| {
        patterns
            .iter()
            .any(|p| Regex::new(p).unwrap().is_match(path))
    };
    for path in [
        "/w/proj/.zcode",
        "/w/proj/.zcode/x",
        "/w/proj/.copilot/a",
        "/w/proj/.clinerules",
        "/w/proj/.clinerules/rules/a.md",
        "/w/proj/.opencode/plugins/x.ts",
        "/w/proj/.opencode/plugin/x.ts",
        "/w/proj/pkg/.OpenCode/plugins/x.ts",
        "/w/proj/.gemini/settings.json",
        "/w/proj/.kiro/hooks/a.json",
        "/w/proj/.roo/mcp.json",
        "/w/proj/.windsurf/rules/a.md",
        "/w/proj/.continue/config.yaml",
        "/w/proj/.pi/extensions/a.ts",
        "/w/proj/.omp/hooks/a.ts",
        "/w/proj/.agents/skills/x/SKILL.md",
        "/w/proj/.husky/pre-commit",
        "/w/proj/GEMINI.md",
        "/w/proj/opencode.json",
        "/w/proj/.github/copilot-instructions.md",
        "/w/proj/.github/instructions/a.md",
        "/w/proj/.github/prompts/a.md",
        "/w/proj/.github/hooks/a.json",
    ] {
        assert!(denied(path), "{path}");
    }
    for path in [
        "/w/proj/src/.zcode-notes.ts",
        "/w/proj/dist/index.js",
        "/w/proj/node_modules/.cache/x",
        "/w/proj/tests/hooks/a.test.ts",
        "/w/proj/.github/dependabot.yml",
        "/w/proj/.github/ISSUE_TEMPLATE/bug.md",
        "/w/proj/.vscode-test/x",
        "/w/other/.zcode/x",
    ] {
        assert!(!denied(path), "{path}");
    }
}

#[test]
fn composed_profile_orders_denials_last_and_covers_credentials() {
    let mut value = input("/w/proj");
    value.write_denials = vec![PathBuf::from("/w/proj/tools/hook")];
    let profile = workspace_profile::compose(&value, &[], &[]).unwrap();
    let lines: Vec<&str> = profile.lines().collect();
    assert_eq!(
        &lines[..3],
        ["(version 1)", "(deny default)", "(deny file-link)"]
    );
    assert!(!profile.contains("network"));
    let credential = lines
        .iter()
        .rposition(|line| line.starts_with("(deny file-read* file-write* (regex"))
        .unwrap();
    assert_eq!(credential, lines.len() - 1);
    let hook = workspace_profile::denial_patterns(
        Path::new("/w/proj"),
        &[PathBuf::from("/w/proj/tools/hook")],
    )
    .unwrap();
    for pattern in &hook {
        assert!(profile.contains(&seatbelt_string(pattern)), "{pattern}");
    }
    let allow = lines
        .iter()
        .position(|line| line.starts_with("(allow file-write*"))
        .unwrap();
    let git = lines
        .iter()
        .position(|line| line.starts_with("(deny file-write* (regex"))
        .unwrap();
    assert!(allow < git);
}

#[test]
fn only_the_user_database_mach_service_is_reachable() {
    let profile = workspace_profile::compose(&input("/w/proj"), &[], &[]).unwrap();
    let lookups: Vec<&str> = profile
        .lines()
        .filter(|line| line.contains("mach-lookup") || line.contains("global-name"))
        .collect();
    assert_eq!(
        lookups,
        ["(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))"]
    );
    for service in [
        "opendirectoryd.api",
        "SecurityServer",
        "securityd",
        "secd",
        "keychain",
        "authd",
        "(allow mach-lookup)",
        "global-name-prefix",
    ] {
        assert!(!profile.contains(service), "{service}");
    }
}

#[test]
fn privileged_binaries_are_denied_execution() {
    let profile = workspace_profile::compose(&input("/w/proj"), &[], &[]).unwrap();
    assert!(profile.contains("(deny process-exec (literal \"/usr/bin/sudo\")"));
}

#[test]
fn existing_profiles_ignore_the_new_fields_and_linux_rejects_this_one() {
    let error = bubblewrap_argv(&input("/w/proj")).unwrap_err();
    assert_eq!(error.reason_code, PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE);
}

#[test]
fn helper_denials_cover_every_case_and_each_ancestor() {
    let ws = Path::new("/w/proj");
    let patterns =
        workspace_profile::denial_patterns(ws, &[PathBuf::from("/w/proj/.husky/_")]).unwrap();
    let denied = |path: &str| {
        patterns
            .iter()
            .any(|p| Regex::new(p).unwrap().is_match(path))
    };
    for path in [
        "/w/proj/.husky/_",
        "/w/proj/.husky/_/pre-commit",
        "/w/proj/.HUSKY/_/pre-commit",
        // Renaming or replacing the ancestor would redirect the hook path.
        "/w/proj/.husky",
        "/w/proj/.Husky",
    ] {
        assert!(denied(path), "{path}");
    }
    for path in ["/w/proj/.husky/install.mjs", "/w/proj/src", "/w/proj"] {
        assert!(!denied(path), "{path}");
    }
    for outside in ["/w/other/x", "/w/proj"] {
        assert!(workspace_profile::denial_patterns(ws, &[PathBuf::from(outside)]).is_err());
    }
}

#[test]
fn nothing_protected_can_be_built_elsewhere_and_moved_in() {
    let head =
        Regex::new(&workspace_profile::bare_head_pattern(Path::new("/w/proj")).unwrap()).unwrap();
    for denied in ["/w/proj/HEAD", "/w/proj/vendor/x/head", "/w/proj/.git/HEAD"] {
        assert!(head.is_match(denied), "{denied}");
    }
    for allowed in ["/w/proj/HEAD.lock", "/w/proj/src/header.h", "/w/other/HEAD"] {
        assert!(!head.is_match(allowed), "{allowed}");
    }
    let profile = workspace_profile::compose(&input("/w/proj"), &[], &[]).unwrap();
    let lines: Vec<&str> = profile.lines().collect();
    let private = Path::new("/private/tmp/guard-private");
    let mut rules = vec![
        workspace_profile::git_exec_pattern(private).unwrap(),
        workspace_profile::bare_head_pattern(private).unwrap(),
    ];
    rules.extend(workspace_profile::protected_patterns(private).unwrap());
    for pattern in &rules {
        assert!(profile.contains(&seatbelt_string(pattern)), "{pattern}");
    }
    assert!(lines.contains(&"(deny file-write* (literal \"/w/proj\"))"));
    // Only the repository's own HEAD and its reflog are reopened, after the
    // rule closing them.
    assert!(head.is_match("/w/proj/.git/logs/HEAD"));
    let reopen = lines
        .iter()
        .position(|line| {
            *line
                == "(allow file-write* (literal \"/w/proj/.git/HEAD\") (literal \"/w/proj/.git/logs/HEAD\"))"
        })
        .unwrap();
    let workspace_head =
        seatbelt_string(&workspace_profile::bare_head_pattern(Path::new("/w/proj")).unwrap());
    let closed = lines
        .iter()
        .position(|line| line.contains(&workspace_head))
        .unwrap();
    assert!(closed < reopen);
}

#[test]
fn reopened_reflog_cannot_become_a_bare_repository() {
    let ws = Path::new("/w/proj");
    let store = Regex::new(&workspace_profile::ref_store_repository_pattern(ws).unwrap()).unwrap();
    for denied in [
        "/w/proj/.git/logs/config",
        "/w/proj/.git/logs/objects",
        "/w/proj/.git/logs/objects/ab/cd",
        "/w/proj/.git/LOGS/Commondir",
        "/w/proj/.git/refs/remotes/o/config.lock",
        "/w/proj/.git/logs/refs/remotes/o/gitdir",
        "/w/proj/sub/.git/logs/objects",
    ] {
        assert!(store.is_match(denied), "{denied}");
    }
    for allowed in [
        "/w/proj/.git/logs/HEAD",
        "/w/proj/.git/logs/refs/heads/main",
        "/w/proj/.git/refs/heads/feat/x",
        "/w/proj/.git/refs/heads/fix/config",
        "/w/proj/.git/refs/heads/fix/config.lock",
        "/w/proj/.git/logs/refs/heads/fix/config",
        "/w/proj/.git/refs/tags/objects/v1",
        "/w/proj/.git/refs/remotes/o/fix/config",
        "/w/proj/.git/refs/objects",
        "/w/proj/.git/objects/ab/cd",
        "/w/proj/.git/config",
        "/w/proj/src/logs/config",
    ] {
        assert!(!store.is_match(allowed), "{allowed}");
    }
    let carrier = Regex::new(&workspace_profile::head_carrier_pattern(ws).unwrap()).unwrap();
    for denied in [
        "/w/proj/.git/logs",
        "/w/proj/.git/logs/refs",
        "/w/proj/.git/logs/refs/remotes/origin",
        "/w/proj/.git/refs",
        "/w/proj/.git/Refs/remotes",
        "/w/proj/.git/refs/remotes/origin",
    ] {
        assert!(carrier.is_match(denied), "{denied}");
    }
    for allowed in [
        "/w/proj/.git/refs/heads",
        "/w/proj/.git/logs/refs/heads",
        "/w/proj/.git/logs/HEAD",
        "/w/proj/.git/refs/remotes/origin/main",
    ] {
        assert!(!carrier.is_match(allowed), "{allowed}");
    }
    let profile = workspace_profile::compose(&input("/w/proj"), &[], &[]).unwrap();
    for root in [ws, Path::new("/private/tmp/guard-private")] {
        let store = workspace_profile::ref_store_repository_pattern(root).unwrap();
        let carrier = workspace_profile::head_carrier_pattern(root).unwrap();
        assert!(profile.contains(&format!(
            "(deny file-write* (regex {}))",
            seatbelt_string(&store)
        )));
        assert!(profile.contains(&format!(
            "(deny file-write-unlink (regex {}))",
            seatbelt_string(&carrier)
        )));
    }
}

#[test]
fn directories_above_the_workspace_can_be_listed_but_not_read() {
    let profile = workspace_profile::compose(&input("/w/team/proj"), &[], &[]).unwrap();
    let listing = profile
        .lines()
        .find(|line| line.starts_with("(allow file-read-data"))
        .unwrap();
    assert_eq!(
        listing,
        "(allow file-read-data (literal \"/w/team\") (literal \"/w\") (literal \"/\"))"
    );
    assert!(!profile.contains("(subpath \"/w/team\")"));
    assert!(!profile.contains("(subpath \"/w\")"));
    // The credential denials still come after the listing grant.
    let at = |needle: &str| profile.find(needle).unwrap();
    assert!(at("(allow file-read-data") < at("(deny file-read* file-write* (regex"));
}

#[test]
fn system_links_and_toolchain_config_stay_readable() {
    let profile = workspace_profile::compose(&input("/w/proj"), &[], &[]).unwrap();
    let metadata = profile
        .lines()
        .find(|line| line.starts_with("(allow file-read-metadata"))
        .unwrap();
    for link in ["/etc", "/tmp", "/var"] {
        if Path::new(link).exists() {
            assert!(
                metadata.contains(&format!("(literal \"{link}\")")),
                "{link}"
            );
        }
    }
    for file in [
        "/private/var/select/developer_dir",
        "/opt/homebrew/etc/gitconfig",
        "/opt/homebrew/etc/openssl@3/openssl.cnf",
        "/private/etc/ssl/openssl.cnf",
    ] {
        if Path::new(file).exists() {
            assert!(profile.contains(&format!("(literal \"{file}\")")), "{file}");
        }
    }
    assert!(!profile.contains("(subpath \"/private/var\")"));
}

#[test]
fn a_linked_worktree_writes_only_shared_stores_and_its_admin_entry() {
    let mut value = input("/w/proj");
    value.linked_git = Some(super::super::workspace_linked::LinkedGit {
        common: PathBuf::from("/w/main/.git"),
        admin: PathBuf::from("/w/main/.git/worktrees/proj"),
    });
    let profile = workspace_profile::compose(&value, &[], &[]).unwrap();
    let line = |prefix: &str, needle: &str| {
        profile
            .lines()
            .any(|line| line.starts_with(prefix) && line.contains(needle))
    };
    assert!(line("(allow process-exec", "(subpath \"/w/main\")"));
    assert!(line("(allow file-read*", "(subpath \"/w/main\")"));
    for tree in ["objects", "refs", "logs"] {
        let needle = format!("(subpath \"/w/main/.git/{tree}\")");
        assert!(line("(allow file-write*", &needle), "{tree}");
    }
    assert!(line(
        "(allow file-write*",
        "(literal \"/w/main/.git/packed-refs\")"
    ));
    assert!(line("(deny file-write*", "(literal \"/w/main/.git\")"));
    for file in ["index", "HEAD", "logs/HEAD"] {
        let needle = format!("(literal \"/w/main/.git/worktrees/proj/{file}\")");
        assert!(line("(allow file-write*", &needle), "{file}");
    }
    let logs = "(literal \"/w/main/.git/worktrees/proj/logs\")";
    let allow = profile
        .lines()
        .position(|line| line.starts_with("(allow file-write*") && line.contains(logs))
        .unwrap();
    let unlink = profile
        .lines()
        .position(|line| line == format!("(deny file-write-unlink {logs})"))
        .unwrap();
    assert!(allow < unlink);
    assert!(!profile.contains("(subpath \"/w/main/.git\")"));
    assert!(!profile.contains("(subpath \"/w/main/.git/worktrees"));
    // An admin entry anywhere but directly under the shared `worktrees`.
    value.linked_git = Some(super::super::workspace_linked::LinkedGit {
        common: PathBuf::from("/w/main/.git"),
        admin: PathBuf::from("/w/main/.git/proj"),
    });
    assert!(workspace_profile::compose(&value, &[], &[]).is_err());
}

#[test]
fn every_profile_string_fits_seatbelts_literal_limit() {
    // `sandbox-exec` fails with "Error reading string" once one literal
    // reaches about 1,023 bytes. The first is a typical macOS temporary
    // workspace; the second needs escaping in every protected pattern.
    let quoted = format!("/private/tmp/{}/workspace", "\"".repeat(150));
    for workspace in [
        "/private/var/folders/x1/abcdefghijklmnopqrstuvwx0000gn/T/guard-work/fix-failing-node-test/workspace",
        quoted.as_str(),
    ] {
        let mut value = input(workspace);
        value.write_denials = vec![PathBuf::from(format!("{workspace}/tools/hook"))];
        let profile = workspace_profile::compose(&value, &[], &[]).unwrap();
        assert!(
            longest_literal(&profile) <= 1000,
            "longest Seatbelt literal for {workspace} is {} bytes",
            longest_literal(&profile)
        );
    }
}

/// Bytes in the longest string literal of `profile`, escapes included.
fn longest_literal(profile: &str) -> usize {
    let (mut literal, mut quoted, mut escaped, mut longest) = (0usize, false, false, 0usize);
    for byte in profile.bytes() {
        if !quoted {
            if byte == b'"' {
                (quoted, literal) = (true, 0);
            }
            continue;
        }
        literal += 1;
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = false;
            longest = longest.max(literal - 1);
        }
    }
    assert!(!quoted);
    longest
}

#[test]
fn a_read_grant_is_one_regular_file_and_nothing_else() {
    let directory = std::env::temp_dir().join(format!("guard-read-grant-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let directory = directory.canonicalize().unwrap();
    let script = directory.join("check.py");
    std::fs::write(&script, "print(1)\n").unwrap();
    let link = directory.join("link.py");
    std::os::unix::fs::symlink(&script, &link).unwrap();
    let granted = |roots: Vec<PathBuf>| {
        let mut value = input("/w/proj");
        value.read_only_roots = roots;
        workspace_profile::compose(&value, &[], &[])
    };
    let profile = granted(vec![script.clone()]).unwrap();
    assert!(profile.contains(&script.to_string_lossy().into_owned()));
    assert!(granted(vec![directory.clone()]).is_err());
    assert!(granted(vec![link]).is_err());
    assert!(granted(vec![PathBuf::from("check.py")]).is_err());
    assert!(granted(vec![PathBuf::from("/w/proj/check.py")]).is_err());
    assert!(granted(vec![directory.join("missing.py")]).is_err());
    let _ = std::fs::remove_dir_all(&directory);
}
