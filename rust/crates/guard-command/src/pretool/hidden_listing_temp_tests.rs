//! Hidden documents of a checkout outside the home directory, where
//! `git worktree add` often leaves one: `/tmp` or the private temporary
//! directory.

use super::repository_plugin_manifest;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct Layout {
    home: PathBuf,
    main: PathBuf,
    linked: PathBuf,
    temp: PathBuf,
    base: PathBuf,
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.temp);
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// A checkout below home with a linked worktree in `/tmp`, registered the way
/// Git registers one: a `.git` file naming an admin entry under the common
/// directory, and that entry's backlink naming the worktree.
fn layout() -> Layout {
    let nonce = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let label = format!("guard-hidden-temp-{}-{nonce}", std::process::id());
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(&label);
    std::fs::create_dir_all(base.join("home/app/.git/worktrees/app-fix")).unwrap();
    let base = std::fs::canonicalize(base).unwrap();
    let home = base.join("home");
    let main = home.join("app");
    let temp = std::fs::canonicalize("/tmp").unwrap().join(&label);
    let linked = temp.join("app-fix");
    std::fs::create_dir_all(&linked).unwrap();
    let admin = main.join(".git/worktrees/app-fix");
    std::fs::write(
        linked.join(".git"),
        format!("gitdir: {}\n", admin.display()),
    )
    .unwrap();
    std::fs::write(admin.join("commondir"), "../..\n").unwrap();
    std::fs::write(
        admin.join("gitdir"),
        format!("{}\n", linked.join(".git").display()),
    )
    .unwrap();
    Layout {
        home,
        main,
        linked,
        temp,
        base,
    }
}

fn plant(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "{\"name\": \"app\"}\n").unwrap();
}

fn read(path: &Path, home: &Path, cwd: &Path) -> bool {
    super::super::bounded_structured_file_read_target(
        path.to_str().unwrap(),
        home.to_str(),
        cwd.to_str(),
    )
}

fn edit(path: &Path, home: &Path, cwd: &Path) -> bool {
    crate::pretool::safe_writes::bounded_structured_file_write_target(
        path.to_str().unwrap(),
        home.to_str(),
        cwd.to_str(),
    )
}

#[test]
fn a_linked_worktree_in_tmp_reads_and_edits_its_plugin_manifests() {
    let layout = layout();
    let manifests = [
        ".claude-plugin/plugin.json",
        "integrations/claude-code-plugin/.claude-plugin/plugin.json",
        "tests/fixtures/good-plugin/.codex-plugin/plugin.json",
    ];
    for manifest in manifests {
        plant(&layout.linked.join(manifest));
    }
    // From inside the worktree, and from the main checkout it was added from.
    for cwd in [&layout.linked, &layout.main] {
        for manifest in manifests {
            let path = layout.linked.join(manifest);
            assert!(
                read(&path, &layout.home, cwd),
                "read {manifest} from {}",
                cwd.display()
            );
            assert!(
                edit(&path, &layout.home, cwd),
                "edit {manifest} from {}",
                cwd.display()
            );
        }
    }
}

#[test]
fn files_a_tool_runs_from_are_not_plugin_manifests() {
    let layout = layout();
    for name in [
        ".vscode/tasks.json",
        ".cargo/config.toml",
        ".claude-plugin/.mcp.json",
        ".claude-plugin/.hooks/run.json",
        // Beside the manifest, but not the manifest.
        ".claude-plugin/runner.py",
        ".claude-plugin/install.sh",
        ".codex-plugin/hooks.json",
        ".claude-plugin/nested/plugin.json",
        ".github/.claude-plugin/plugin.json",
    ] {
        let path = layout.linked.join(name);
        plant(&path);
        assert!(
            !repository_plugin_manifest(&path, layout.home.to_str(), layout.linked.to_str()),
            "{name}"
        );
    }
    let manifest = layout.linked.join(".codex-plugin/plugin.json");
    plant(&manifest);
    assert!(repository_plugin_manifest(
        &manifest,
        layout.home.to_str(),
        layout.linked.to_str()
    ));
}

#[test]
fn checkouts_in_tmp_that_are_not_this_repository_keep_their_review() {
    let layout = layout();
    // An unrelated checkout beside the worktree is a sibling.
    let other = layout.temp.join("other");
    std::fs::create_dir_all(other.join(".git")).unwrap();
    plant(&other.join(".codex-plugin/plugin.json"));
    // A `.git` file that names the worktree's admin entry, whose backlink
    // names a different directory, nominates nothing.
    let stray = layout.temp.join("stray");
    std::fs::create_dir_all(&stray).unwrap();
    std::fs::write(
        stray.join(".git"),
        format!(
            "gitdir: {}\n",
            layout.main.join(".git/worktrees/app-fix").display()
        ),
    )
    .unwrap();
    plant(&stray.join(".codex-plugin/plugin.json"));
    for path in [
        other.join(".codex-plugin/plugin.json"),
        stray.join(".codex-plugin/plugin.json"),
    ] {
        assert!(
            !read(&path, &layout.home, &layout.main),
            "{}",
            path.display()
        );
        assert!(
            !edit(&path, &layout.home, &layout.main),
            "{}",
            path.display()
        );
    }
}

#[test]
fn other_hidden_documents_of_a_linked_worktree_keep_their_review_from_the_main_checkout() {
    let layout = layout();
    let notes = layout.linked.join(".notes/draft.md");
    let listing = layout.linked.join(".claude-plugin/marketplace.json");
    plant(&notes);
    plant(&listing);
    assert!(!read(&notes, &layout.home, &layout.main));
    assert!(!edit(&notes, &layout.home, &layout.main));
    assert!(read(&listing, &layout.home, &layout.main));
    assert!(edit(&listing, &layout.home, &layout.main));
    // Inside the worktree, its own hidden notes are the session's own tree.
    assert!(read(&notes, &layout.home, &layout.linked));
}
