use guard_secure_fs::{read_bounded, SecureReadError};
use std::fs::{self, OpenOptions};
use std::io::Write;

fn fixture_root(name: &str) -> std::path::PathBuf {
    let temporary_root = fs::canonicalize(std::env::temp_dir())
        .map(host_spelling)
        .unwrap_or_else(|_| std::env::temp_dir());
    temporary_root.join(format!("guard-secure-fs-{name}-{}", std::process::id()))
}

/// `canonicalize` spells Windows paths in the verbatim `\\?\C:\` form, which
/// source classification refuses as a glob. Hosts send the ordinary drive
/// form, so the fixture root uses that. A root on a share canonicalizes to
/// `\\?\UNC\server\share\...`, whose ordinary spelling is
/// `\\server\share\...`.
fn host_spelling(path: std::path::PathBuf) -> std::path::PathBuf {
    let Some(stripped) = path.to_str().and_then(|text| text.strip_prefix(r"\\?\")) else {
        return path;
    };
    if let Some(share) = stripped.strip_prefix(r"UNC\") {
        return format!(r"\\{share}").into();
    }
    if stripped.as_bytes().get(1) == Some(&b':') {
        return stripped.into();
    }
    path
}

#[test]
fn bounded_read_rejects_truncation_limit_before_materializing_more_bytes() {
    let dir = fixture_root("truncation");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("source.rs");
    fs::write(&path, b"0123456789").unwrap();

    assert!(matches!(
        read_bounded(&path, 4),
        Err(SecureReadError::TooLarge)
    ));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn bounded_read_rejects_source_growth_beyond_limit() {
    let dir = fixture_root("growth");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("source.rs");
    fs::write(&path, b"safe").unwrap();
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(b" growth").unwrap();
    drop(file);

    assert!(matches!(
        read_bounded(&path, 4),
        Err(SecureReadError::TooLarge)
    ));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn agent_plan_documents_are_scannable_and_keep_path_floors() {
    use guard_secure_fs::classify_scannable_source_path;
    let dir = fixture_root("agent-plans");
    let home = dir.join("home");
    let cwd = dir.join("workspace");
    fs::create_dir_all(&cwd).unwrap();
    for relative in [
        ".codex/plans/rollout-todo.md",
        ".codex/plans/evidence/review-run/README.md",
        ".claude/plans/quiet-plan.md",
    ] {
        let path = home.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "inert plan").unwrap();
        for allow_external in [true, false] {
            assert!(
                classify_scannable_source_path(
                    path.to_str().unwrap(),
                    &cwd,
                    Some(&home),
                    allow_external
                )
                .allowed,
                "{relative}"
            );
        }
    }
    for relative in [
        ".codex/config.toml",
        ".codex/notes.md",
        ".codex/plans/auth.md",
        ".codex/plans/token-rotation.md",
        ".codex/plans/.hidden/plan.md",
        ".codex/plans/state.json",
        ".claude/plans/../settings.md",
    ] {
        let path = home.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "synthetic sensitive fixture").unwrap();
        assert!(
            !classify_scannable_source_path(path.to_str().unwrap(), &cwd, Some(&home), true)
                .allowed,
            "{relative}"
        );
    }
    #[cfg(unix)]
    {
        let secret = home.join(".codex/auth.json");
        fs::write(&secret, "synthetic sensitive fixture").unwrap();
        let link = home.join(".codex/plans/linked.md");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        assert!(
            !classify_scannable_source_path(link.to_str().unwrap(), &cwd, Some(&home), true)
                .allowed
        );
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn omp_skill_sources_keep_sensitive_and_hidden_path_floors() {
    use guard_secure_fs::classify_scannable_source_path;
    let dir = fixture_root("omp-skill");
    let home = dir.join("home");
    let cwd = dir.join("workspace");
    let skill = home.join(".agent/skills/example/SKILL.md");
    fs::create_dir_all(skill.parent().unwrap()).unwrap();
    fs::create_dir_all(&cwd).unwrap();
    fs::write(&skill, "inert reference").unwrap();
    assert!(
        classify_scannable_source_path(skill.to_str().unwrap(), &cwd, Some(&home), true).allowed
    );
    let report = home.join(".agent/artifacts/report.md");
    fs::create_dir_all(report.parent().unwrap()).unwrap();
    fs::write(&report, "inert report").unwrap();
    assert!(
        classify_scannable_source_path(report.to_str().unwrap(), &cwd, Some(&home), true).allowed
    );
    for relative in [
        ".agent/auth.json",
        ".agent/artifacts/auth.md",
        ".agent/artifacts/.hidden/report.md",
        ".agent/artifacts/report.json",
        ".agent/skills/example/.env",
        ".agent/skills/example/../secret.txt",
    ] {
        let path = home.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "synthetic sensitive fixture").unwrap();
        assert!(
            !classify_scannable_source_path(path.to_str().unwrap(), &cwd, Some(&home), true)
                .allowed
        );
    }
    #[cfg(unix)]
    {
        let artifact_link = home.join(".agent/artifacts/linked.md");
        std::os::unix::fs::symlink(&report, &artifact_link).unwrap();
        assert!(
            !classify_scannable_source_path(
                artifact_link.to_str().unwrap(),
                &cwd,
                Some(&home),
                true
            )
            .allowed
        );
        let link = home.join(".agent/skills/example/linked.md");
        std::os::unix::fs::symlink(&skill, &link).unwrap();
        assert!(
            !classify_scannable_source_path(link.to_str().unwrap(), &cwd, Some(&home), true)
                .allowed
        );
    }
    fs::remove_dir_all(dir).unwrap();
}

/// A workspace reached through a linked ancestor is an ordinary workspace.
/// macOS resolves `/tmp` to `/private/tmp`, so an agent that joins a relative
/// path onto its own `/tmp` cwd produces an absolute path with a linked
/// component. Classification used to refuse that before comparing the
/// resolved target with the workspace, which denied every read in such a
/// checkout. The link still has to stay inside the workspace.
#[cfg(unix)]
#[test]
fn a_workspace_spelled_through_a_linked_ancestor_still_classifies_its_own_sources() {
    use guard_secure_fs::classify_source_path;
    let dir = fixture_root("linked-workspace");
    let real = dir.join("real");
    let home = dir.join("home");
    let workspace = real.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::create_dir_all(&home).unwrap();
    fs::write(workspace.join("src/index.ts"), "export const one = 1;\n").unwrap();
    fs::write(workspace.join(".env"), "SYNTHETIC_FIXTURE=1\n").unwrap();
    fs::write(home.join("outside.ts"), "export const two = 2;\n").unwrap();

    // The same tree named through a link, exactly as a `/tmp` spelling reaches
    // the hook on macOS.
    let linked_root = dir.join("linked");
    std::os::unix::fs::symlink(&real, &linked_root).unwrap();
    let linked_workspace = linked_root.join("workspace");
    let linked_source = linked_workspace.join("src/index.ts");

    let allowed = classify_source_path(
        linked_source.to_str().unwrap(),
        &linked_workspace,
        Some(&home),
        false,
    );
    assert!(
        allowed.allowed,
        "linked workspace spelling denied: {}",
        allowed.reason_code
    );
    assert_eq!(allowed.resolved_path, fs::canonicalize(&linked_source).ok());

    // A link planted below the root is still refused, so admitting the
    // root's own linked ancestry cannot present a credential store as
    // ordinary source.
    let planted = workspace.join("src/settings.ts");
    std::os::unix::fs::symlink(workspace.join(".env"), &planted).unwrap();
    assert_eq!(
        classify_source_path(
            linked_workspace.join("src/settings.ts").to_str().unwrap(),
            &linked_workspace,
            Some(&home),
            false,
        )
        .reason_code,
        "symlink_in_path"
    );

    // A target outside `SENSITIVE_SEARCH_BASENAMES` is refused on the same
    // rule. The in-workspace screens never see it, so the link check is what
    // keeps a credential file from arriving under a source-shaped name.
    fs::write(workspace.join("src/deploy.key"), "SYNTHETIC_FIXTURE\n").unwrap();
    let planted_family = workspace.join("src/config.ts");
    std::os::unix::fs::symlink(workspace.join("src/deploy.key"), &planted_family).unwrap();
    assert_eq!(
        classify_source_path(
            linked_workspace.join("src/config.ts").to_str().unwrap(),
            &linked_workspace,
            Some(&home),
            false,
        )
        .reason_code,
        "symlink_in_path"
    );

    // Even when the link resolves to ordinary source inside the workspace.
    let benign_link = workspace.join("src/alias.ts");
    std::os::unix::fs::symlink(workspace.join("src/index.ts"), &benign_link).unwrap();
    assert_eq!(
        classify_source_path(
            linked_workspace.join("src/alias.ts").to_str().unwrap(),
            &linked_workspace,
            Some(&home),
            false,
        )
        .reason_code,
        "symlink_in_path"
    );

    // A link inside the tree that points back at the root cannot stand in
    // for the root and hide the components below itself.
    let self_link = workspace.join("self");
    std::os::unix::fs::symlink(&workspace, &self_link).unwrap();
    assert_eq!(
        classify_source_path(
            linked_workspace.join("self/src/index.ts").to_str().unwrap(),
            &linked_workspace,
            Some(&home),
            false,
        )
        .reason_code,
        "symlink_in_path"
    );

    // A link that leaves the workspace is still refused for leaving it.
    let escape = workspace.join("src/escape.ts");
    std::os::unix::fs::symlink(home.join("outside.ts"), &escape).unwrap();
    assert_eq!(
        classify_source_path(
            linked_workspace.join("src/escape.ts").to_str().unwrap(),
            &linked_workspace,
            Some(&home),
            false,
        )
        .reason_code,
        "symlink_in_path"
    );

    fs::remove_dir_all(dir).unwrap();
}
