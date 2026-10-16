use super::allowances::{codex_notes_document, worktree_gitfile};
use super::repository_hidden_directory;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn fixture_root() -> PathBuf {
    let nonce = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "guard-hidden-listing-{}-{nonce}",
            std::process::id()
        ));
    std::fs::create_dir_all(&root).unwrap();
    crate::runtime_read_paths::canonicalize_text(&root).unwrap()
}

fn listed(value: &Path, home: &Path, cwd: &Path) -> bool {
    repository_hidden_directory(value.to_str().unwrap(), home.to_str(), cwd.to_str())
}

#[test]
fn hidden_directories_inside_a_work_tree_list_quietly() {
    let root = fixture_root();
    let home = root.join("home");
    let repo = home.join("app");
    for directory in [".git/refs", ".deploy-production.lock.d", "scripts"] {
        std::fs::create_dir_all(repo.join(directory)).unwrap();
    }
    assert!(listed(
        &repo.join(".deploy-production.lock.d"),
        &home,
        &repo
    ));
    assert!(listed(&repo.join(".git"), &home, &repo));
    // The session may list a sibling checkout's lock directory as well.
    let other = home.join("other");
    assert!(listed(
        &repo.join(".deploy-production.lock.d"),
        &home,
        &other
    ));
    assert!(repository_hidden_directory(
        ".deploy-production.lock.d",
        home.to_str(),
        repo.to_str()
    ));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn credential_agent_and_unrepositoried_hidden_directories_stay_guarded() {
    let root = fixture_root();
    let home = root.join("home");
    let repo = home.join("app");
    let plain = home.join("plain");
    for directory in [
        repo.join(".git"),
        repo.join(".codex/sessions"),
        repo.join(".env.d"),
        repo.join(".ssh"),
        repo.join(".npm/_cacache"),
        repo.join(".password-store"),
        home.join(".ssh"),
        plain.join(".cache"),
    ] {
        std::fs::create_dir_all(directory).unwrap();
    }
    std::fs::write(repo.join(".lockfile"), "pid\n").unwrap();
    for denied in [
        repo.join(".codex"),
        repo.join(".codex/sessions"),
        repo.join(".env.d"),
        repo.join(".ssh"),
        home.join(".ssh"),
        plain.join(".cache"),
        repo.join(".npm/_cacache"),
        repo.join(".password-store"),
        repo.join("missing.d/.x"),
    ] {
        assert!(!listed(&denied, &home, &repo), "{}", denied.display());
    }
    for value in ["~/.ssh", "app/../.ssh", "$HOME/.ssh", ".git*", ""] {
        assert!(
            !repository_hidden_directory(value, home.to_str(), repo.to_str()),
            "{value}"
        );
    }
    // Hidden regular files may be listed (names and metadata only) under the
    // same screens, but credential-named ones and links into guarded trees
    // may not.
    std::fs::write(repo.join(".env"), "").unwrap();
    std::fs::write(repo.join(".npmrc"), "").unwrap();
    std::fs::write(home.join(".ssh/id_rsa"), "key").unwrap();
    assert!(listed(&repo.join(".lockfile"), &home, &repo));
    for denied in [
        repo.join(".env"),
        repo.join(".npmrc"),
        home.join(".ssh/id_rsa"),
    ] {
        assert!(!listed(&denied, &home, &repo), "{}", denied.display());
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(home.join(".ssh"), repo.join(".keys")).unwrap();
        assert!(!listed(&repo.join(".keys"), &home, &repo));
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn tool_shim_directories_below_a_sibling_work_tree_list_quietly() {
    let root = fixture_root();
    let home = root.join("home");
    let session = home.join("code/app");
    let sibling = home.join("code/app-fix");
    let plain = home.join("code/plain");
    let outside = root.join("outside/app");
    for directory in [
        session.join(".git"),
        sibling.join("node_modules/.bin"),
        sibling.join("packages/web/.turbo"),
        sibling.join("node_modules/.ssh"),
        sibling.join("node_modules/.aws"),
        sibling.join("node_modules/.codex"),
        plain.join("node_modules/.bin"),
        outside.join(".git"),
        outside.join("node_modules/.bin"),
        home.join(".ssh"),
    ] {
        std::fs::create_dir_all(directory).unwrap();
    }
    // A linked worktree marks its root with a `.git` file.
    std::fs::write(
        sibling.join(".git"),
        "gitdir: /src/app/.git/worktrees/app-fix\n",
    )
    .unwrap();
    std::fs::write(sibling.join("node_modules/.bin/vitest"), "#!/bin/sh\n").unwrap();
    for allowed in [
        sibling.join("node_modules/.bin"),
        sibling.join("node_modules/.bin/vitest"),
        sibling.join("packages/web/.turbo"),
    ] {
        assert!(listed(&allowed, &home, &session), "{}", allowed.display());
    }
    // Credential and agent stores keep their guard below a work tree, and a
    // hidden directory in a plain folder or outside home has no work tree
    // to vouch for it.
    for denied in [
        sibling.join("node_modules/.ssh"),
        sibling.join("node_modules/.aws"),
        sibling.join("node_modules/.codex"),
        plain.join("node_modules/.bin"),
        outside.join("node_modules/.bin"),
    ] {
        assert!(!listed(&denied, &home, &session), "{}", denied.display());
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(home.join(".ssh"), sibling.join("node_modules/.keys")).unwrap();
        assert!(!listed(
            &sibling.join("node_modules/.keys"),
            &home,
            &session
        ));
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn only_a_short_well_formed_worktree_gitfile_is_readable() {
    let root = fixture_root();
    let worktree = root.join("app-fix");
    std::fs::create_dir_all(&worktree).unwrap();
    let gitfile = worktree.join(".git");
    std::fs::write(&gitfile, "gitdir: /src/app/.git/worktrees/app-fix\n").unwrap();
    assert!(worktree_gitfile(&gitfile));

    for forged in [
        "gitdir: \n".to_owned(),
        "[core]\n\tbare = false\n".to_owned(),
        "gitdir: /a\nsshCommand = id\n".to_owned(),
        format!("gitdir: /{}\n", "a".repeat(2048)),
    ] {
        std::fs::write(&gitfile, forged.as_bytes()).unwrap();
        assert!(!worktree_gitfile(&gitfile), "{forged:?}");
    }
    let hidden = root.join(".hidden/app");
    std::fs::create_dir_all(&hidden).unwrap();
    std::fs::write(hidden.join(".git"), "gitdir: /src/app/.git\n").unwrap();
    assert!(!worktree_gitfile(&hidden.join(".git")));
    let directory = root.join("repo/.git");
    std::fs::create_dir_all(&directory).unwrap();
    assert!(!worktree_gitfile(&directory));
    let config = root.join("repo/config");
    std::fs::write(&config, "gitdir: /src/app/.git\n").unwrap();
    assert!(!worktree_gitfile(&config));
    #[cfg(unix)]
    {
        let linked = root.join("linked");
        std::fs::create_dir_all(&linked).unwrap();
        std::fs::write(root.join("target-gitfile"), "gitdir: /src/app/.git\n").unwrap();
        std::os::unix::fs::symlink(root.join("target-gitfile"), linked.join(".git")).unwrap();
        assert!(!worktree_gitfile(&linked.join(".git")));
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn codex_plan_evidence_reads_but_auth_and_config_do_not() {
    let root = fixture_root();
    let home = root.join("home");
    let plans = home.join(".codex/plans");
    std::fs::create_dir_all(&plans).unwrap();
    for name in ["todo.md", "evidence.json", "notes.txt", "run.sh"] {
        std::fs::write(plans.join(name), "x").unwrap();
    }
    std::fs::write(home.join(".codex/auth.json"), "{}").unwrap();
    std::fs::write(home.join(".codex/config.toml"), "").unwrap();
    // Callers pass the resolved path (`\\?\` verbatim on Windows).
    let resolved = |path: PathBuf| std::fs::canonicalize(path).unwrap();
    for allowed in ["todo.md", "evidence.json", "notes.txt"] {
        assert!(
            codex_notes_document(&resolved(plans.join(allowed)), home.to_str()),
            "{allowed}"
        );
    }
    for denied in [
        plans.join("run.sh"),
        home.join(".codex/auth.json"),
        home.join(".codex/config.toml"),
    ] {
        assert!(
            !codex_notes_document(&resolved(denied.clone()), home.to_str()),
            "{}",
            denied.display()
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
