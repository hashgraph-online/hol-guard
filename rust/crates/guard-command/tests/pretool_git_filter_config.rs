use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;

#[test]
fn unused_global_filters_do_not_block_unrelated_repository_inspection() {
    // Resolve an 8.3 short TEMP spelling (`RUNNER~1`), which Guard refuses as
    // a path proof; agents report the long canonical working directory.
    let temp = if cfg!(windows) {
        canonical_spelling(std::env::temp_dir())
    } else {
        std::env::temp_dir()
    };
    let root = temp.join(format!("guard unused filters {}", std::process::id()));
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = root.join("repository");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(repository.join("src")).unwrap();
    std::fs::write(repository.join("ordinary.txt"), "ordinary fixture\n").unwrap();
    let marker = root.join("filter-executed");
    // Git config interprets backslashes as escapes; raw Windows paths are not
    // valid config values. Quote the shell operand and then the config value.
    let marker_path = marker.to_string_lossy().replace('\\', "/");
    let marker_command = format!("touch '{}'", marker_path.replace('\'', "'\\''"));
    let config_command = serde_json::to_string(&marker_command).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        format!(
            "[filter \"synthetic\"]\n\tclean = {config_command}\n\tsmudge = {config_command}\n"
        ),
    )
    .unwrap();
    let parsed = std::process::Command::new("git")
        .args(["config", "--file"])
        .arg(home.join(".gitconfig"))
        .args(["--get", "filter.synthetic.clean"])
        .output()
        .unwrap();
    assert!(
        parsed.status.success(),
        "filter fixture must be valid Git config: {}",
        String::from_utf8_lossy(&parsed.stderr)
    );
    assert_eq!(
        String::from_utf8(parsed.stdout).unwrap().trim_end(),
        marker_command
    );
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .arg(&repository)
        .status()
        .unwrap()
        .success());
    let controls = github_controls("enabled");
    let quoted_repository = repository
        .to_string_lossy()
        .replace('\\', "/")
        .replace('\'', "'\\''");
    let absolute_status = format!("git --no-pager -C '{quoted_repository}' status --short");
    for harness in ["omp", "zcode"] {
        for command in [
            "git status --short",
            "git -C src status --short",
            "git diff --no-ext-diff --no-textconv",
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&controls),
                None,
                home.to_str(),
                repository.to_str(),
            );
            assert_eq!(
                result.decision, "allow",
                "{harness}: {command}: {}",
                result.reason_code
            );
        }
        let result = evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":absolute_status.as_str()}}),
            Some(&controls),
            None,
            home.to_str(),
            repository.to_str(),
        );
        assert_eq!(
            result.decision, "allow",
            "{harness}: {}: {}",
            absolute_status, result.reason_code
        );
    }
    // Routing into src must not hide a filter attached to a root-level path.
    std::fs::write(
        repository.join(".gitattributes"),
        "ordinary.txt filter=synthetic\n",
    )
    .unwrap();
    for harness in ["omp", "zcode"] {
        for command in [
            "git status --short",
            "git -C src status --short",
            "git diff --no-ext-diff --no-textconv",
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&controls),
                None,
                home.to_str(),
                repository.to_str(),
            );
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            assert_eq!(result.reason_code, "native_git_execution_context_review");
        }
        let result = evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":absolute_status.as_str()}}),
            Some(&controls),
            None,
            home.to_str(),
            repository.to_str(),
        );
        assert_eq!(result.decision, "deny", "{harness}: {absolute_status}");
        assert_eq!(result.reason_code, "native_git_execution_context_review");
    }
    assert!(
        !marker.exists(),
        "inspection must never execute configured filters"
    );
    std::fs::write(repository.join(".gitattributes"), "").unwrap();
    std::fs::create_dir(repository.join("module")).unwrap();
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args([
            "update-index",
            "--add",
            "--cacheinfo",
            "160000,1111111111111111111111111111111111111111,module"
        ])
        .status()
        .unwrap()
        .success());
    for harness in ["omp", "zcode"] {
        let result = evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":"git -C src status --short"}}),
            Some(&controls),
            None,
            home.to_str(),
            repository.to_str(),
        );
        assert_eq!(
            result.reason_code, "native_git_execution_context_review",
            "submodule filter context is not proven"
        );
    }
}

#[test]
fn an_ls_files_modified_listing_answers_for_a_used_clean_filter() {
    let temp = if cfg!(windows) {
        canonical_spelling(std::env::temp_dir())
    } else {
        std::env::temp_dir()
    };
    let root = temp.join(format!("guard ls-files filters {}", std::process::id()));
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = root.join("repository");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&repository).unwrap();
    std::fs::write(repository.join("ordinary.txt"), "ordinary fixture\n").unwrap();
    let marker = root.join("filter-executed");
    let marker_path = marker.to_string_lossy().replace('\\', "/");
    let marker_command = format!("touch '{}'", marker_path.replace('\'', "'\\''"));
    let config_command = serde_json::to_string(&marker_command).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        format!(
            "[filter \"synthetic\"]\n\tclean = {config_command}\n\tsmudge = {config_command}\n"
        ),
    )
    .unwrap();
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .arg(&repository)
        .status()
        .unwrap()
        .success());
    let controls = github_controls("enabled");
    // Selectors answered from the index, the directory walk and `lstat` alone,
    // which never hash a working-tree file.
    let listings = ["git ls-files", "git ls-files -d", "git ls-files --others"];
    // `-m` compares each tracked file with its stored blob, and a comparison
    // the stat data cannot settle reads the file and converts it, which runs
    // the repository's clean filter.
    let comparisons = [
        "git ls-files -m",
        "git ls-files --modified",
        "git ls-files -cm",
    ];
    let judge = |command: &str| {
        evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":command}}),
            Some(&controls),
            None,
            home.to_str(),
            repository.to_str(),
        )
    };
    // A global filter definition no path uses executes nothing.
    for command in listings.iter().chain(&comparisons) {
        let result = judge(command);
        assert_eq!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    std::fs::write(
        repository.join(".gitattributes"),
        "ordinary.txt filter=synthetic\n",
    )
    .unwrap();
    for command in comparisons {
        let result = judge(command);
        assert_eq!(result.decision, "deny", "{command}");
        assert_eq!(
            result.reason_code, "native_git_execution_context_review",
            "{command}"
        );
    }
    // The attached filter changes nothing for a listing that never hashes.
    for command in listings {
        let result = judge(command);
        assert_eq!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
    assert!(
        !marker.exists(),
        "a listing must never execute configured filters"
    );
}
