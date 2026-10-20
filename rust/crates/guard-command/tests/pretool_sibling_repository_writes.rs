#![cfg(unix)]

//! A session started in a folder above its checkouts, or beside the one it
//! edits, still writes that repository through the shell the way a file-edit
//! tool does: `cat /tmp/x.ts > <clone>/src/lib/y.ts`, an append, a quoted
//! heredoc, or a staging copy followed by a write. Hooks, settings,
//! credential files, links and executables keep their review, and so does any
//! folder that is not a repository. Instruction files outside the session
//! continue to require review.

use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::git_helper_fixture::{self as fixture, evaluate_pre_tool_envelope_with_context};

struct Layout {
    root: PathBuf,
    home: PathBuf,
    /// The session folder: a plain directory above the checkouts.
    session: PathBuf,
    clone: PathBuf,
    notes: PathBuf,
    scratch: PathBuf,
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn layout(name: &str) -> Layout {
    layout_at(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/omp-redirect-fixtures")
            .join(format!("{name}-{}", std::process::id())),
        name,
    )
}

fn layout_at(root: PathBuf, name: &str) -> Layout {
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let home = fixture::canonical_spelling(&root).join("home");
    build_layout(root, home, name)
}

/// A layout whose home is spelled through a symlinked parent, the way a
/// harness hands Guard the home the session was started in: on macOS a
/// temporary home is spelled `/var/folders/...` and resolves to
/// `/private/var/...`. The alias is built explicitly (`spelled -> real`) so
/// every platform exercises it, and it sits outside `/tmp` so the sibling
/// route, not the temporary-directory one, answers.
struct SpelledLayout {
    layout: Layout,
    base: PathBuf,
}

impl Drop for SpelledLayout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.layout.scratch);
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn layout_spelled(name: &str) -> SpelledLayout {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/omp-redirect-fixtures")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("real")).unwrap();
    // Only the `spelled` link may differ from the resolved path.
    let base = fixture::canonical_spelling(&base);
    symlink(base.join("real"), base.join("spelled")).unwrap();
    let root = base.join("spelled").join("fixture");
    std::fs::create_dir_all(&root).unwrap();
    let home = root.join("home");
    SpelledLayout {
        layout: build_layout(root, home, name),
        base,
    }
}

fn build_layout(root: PathBuf, home: PathBuf, name: &str) -> Layout {
    let session = home.join("work");
    let clone = home.join("acme-app-clone");
    let notes = home.join("plain-notes");
    for directory in [
        session.clone(),
        notes.clone(),
        clone.join("src/lib"),
        clone.join("src/api/login"),
        clone.join("scripts"),
        clone.join(".git/hooks"),
        clone.join(".git/objects"),
        clone.join(".git/refs"),
    ] {
        std::fs::create_dir_all(directory).unwrap();
    }
    std::fs::write(clone.join("src/lib/auth.ts"), "export const auth = 1;\n").unwrap();
    std::fs::write(clone.join(".env"), "SESSION_KEY=synthetic\n").unwrap();
    std::fs::write(clone.join("AGENTS.md"), "rules\n").unwrap();
    std::fs::write(clone.join(".git/config"), "[core]\n").unwrap();
    std::fs::write(clone.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(clone.join("scripts/run.sh"), "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(
        clone.join("scripts/run.sh"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::fs::write(notes.join("a.md"), "notes\n").unwrap();
    std::fs::write(home.join(".zshrc"), "export PATH\n").unwrap();
    symlink(home.join(".zshrc"), clone.join("src/lib/link.ts")).unwrap();
    symlink(&notes, clone.join("linked")).unwrap();
    let scratch = PathBuf::from(format!("/tmp/hg-redirect-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir(&scratch).unwrap();
    std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(scratch.join("x.ts"), "export const x = 1;\n").unwrap();
    std::fs::write(scratch.join("a.ts"), "export const a = 1;\n").unwrap();
    Layout {
        root,
        home,
        session,
        clone,
        notes,
        scratch,
    }
}

fn permitted(layout: &Layout, cwd: &Path, command: &str) -> bool {
    let evaluate = |harness| {
        let result = evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": "bash", "tool_input": {"command": command}}),
            None,
            None,
            layout.home.to_str(),
            cwd.to_str(),
        );
        result.decision == "allow" && matches!(result.minimum_action.as_str(), "allow" | "warn")
    };
    let omp = evaluate("omp");
    assert_eq!(omp, evaluate("zcode"), "host policy drift: {command}");
    omp
}

#[test]
fn redirects_into_a_sibling_clone_are_the_edits_a_file_tool_makes() {
    let layout = layout("allowed");
    let (clone, scratch) = (layout.clone.display(), layout.scratch.display());
    for command in [
        format!("cat {scratch}/x.ts > {clone}/src/lib/y.ts"),
        format!("cat {scratch}/x.ts > {clone}/src/api/login/route.ts"),
        format!("cat {scratch}/x.ts > {clone}/src/lib/auth.ts"),
        format!("cat {scratch}/x.ts >> {clone}/src/lib/auth.ts"),
        format!("cat {scratch}/x.ts >> {clone}/src/lib/y.ts"),
        format!("cat > {clone}/notes.md <<'EOF'\n# Pending\n- a\nEOF"),
        format!("cat > {clone}/.pending-edits.md <<'EOF'\n# Pending\n- a\nEOF"),
        format!("cat >> {clone}/notes.md <<'EOF'\n- b\nEOF"),
        format!("cp {scratch}/a.ts {scratch}/b.ts && cat {scratch}/a.ts > {clone}/src/lib/y.ts"),
        format!(
            "cp {scratch}/a.ts {scratch}/b.ts && cat {scratch}/a.ts >> {clone}/src/lib/auth.ts"
        ),
    ] {
        assert!(permitted(&layout, &layout.session, &command), "{command}");
    }
}

#[test]
fn a_staging_copy_before_a_write_is_allowed_in_an_ordinary_session_folder_too() {
    let layout = layout("ordinary");
    let scratch = layout.scratch.display();
    for command in [
        format!("cp {scratch}/a.ts {scratch}/b.ts && cat {scratch}/a.ts > src/lib/y.ts"),
        format!("cp {scratch}/a.ts {scratch}/b.ts && cat {scratch}/a.ts >> src/lib/auth.ts"),
        format!("ls src && cat {scratch}/x.ts > src/lib/y.ts"),
        format!("cat {scratch}/x.ts > src/lib/y.ts"),
    ] {
        assert!(permitted(&layout, &layout.clone, &command), "{command}");
    }
}

#[test]
fn protected_targets_links_and_other_folders_keep_their_review() {
    let layout = layout("reviewed");
    let (clone, scratch) = (layout.clone.display(), layout.scratch.display());
    let (home, notes) = (layout.home.display(), layout.notes.display());
    let mut wrongly_allowed = Vec::new();
    for command in [
        // Git control files, hooks, dotenv and harness settings.
        format!("cat {scratch}/x.ts > {clone}/.git/config"),
        format!("cat {scratch}/x.ts >> {clone}/.git/hooks/pre-commit"),
        format!("cat {scratch}/x.ts >> {clone}/.env"),
        format!("cat {scratch}/x.ts > {clone}/.husky/pre-commit"),
        format!("cat {scratch}/x.ts > {clone}/.claude/settings.json"),
        // Existing programs are not truncated, and links are not followed.
        format!("cat {scratch}/x.ts > {clone}/scripts/run.sh"),
        format!("cat {scratch}/x.ts > {clone}/src/lib/link.ts"),
        format!("cat {scratch}/x.ts > {clone}/linked/a.md"),
        // A folder that is not a repository, the home itself and its dotfiles.
        format!("cat {scratch}/x.ts > {notes}/a.md"),
        format!("cat {scratch}/x.ts > {notes}/b.md"),
        format!("cat {scratch}/x.ts > {home}/notes.md"),
        format!("cat {scratch}/x.ts >> {home}/.zshrc"),
        // The same boundaries hold for heredocs.
        format!("cat > {clone}/.git/hooks/pre-commit <<'EOF'\nexit 0\nEOF"),
        format!("cat > {clone}/.env <<'EOF'\nX=1\nEOF"),
        format!("cat > {notes}/b.md <<'EOF'\nx\nEOF"),
        format!("cat > {home}/.zshrc <<'EOF'\nexport X=1\nEOF"),
        format!("cat > {clone}/src/lib/link.ts <<'EOF'\nx\nEOF"),
        // A staging chain keeps every one of them, and any step that could
        // change directory or create a link first.
        format!("cp {scratch}/a.ts {scratch}/b.ts && cat {scratch}/a.ts > {clone}/.git/hooks/pre-commit"),
        format!("cp {scratch}/a.ts {scratch}/b.ts && cat {scratch}/a.ts > {home}/.zshrc"),
        format!("cp {scratch}/a.ts {scratch}/b.ts && cat {scratch}/a.ts > {clone}/.env"),
        format!("cp {scratch}/a.ts {scratch}/b.ts && cat {scratch}/a.ts > {notes}/b.md"),
        format!("ln -s {home}/.zshrc {clone}/src/lib/l.ts && cat {scratch}/a.ts > {clone}/src/lib/l.ts"),
    ] {
        if permitted(&layout, &layout.session, &command) {
            wrongly_allowed.push(command);
        }
    }
    assert!(wrongly_allowed.is_empty(), "{wrongly_allowed:#?}");
}

#[test]
fn instruction_file_heredocs_outside_the_session_remain_reviewed() {
    // A session outside a clone must not turn an instruction-file write into
    // an unsandboxed no-op proof. A newly loaded AGENTS.md can redirect an agent.
    let layout = layout("instruction-heredoc");
    let clone = layout.clone.display();
    let command = format!("cat > {clone}/AGENTS.md <<'EOF'\nmore rules\nEOF");
    assert!(!permitted(&layout, &layout.session, &command), "{command}");
}

#[test]
fn instruction_file_redirects_outside_the_session_remain_reviewed() {
    let layout = layout("instructions");
    let (clone, scratch) = (layout.clone.display(), layout.scratch.display());
    for command in [
        format!("cat {scratch}/x.ts >> {clone}/AGENTS.md"),
        format!("cat {scratch}/x.ts > {clone}/AGENTS.md"),
    ] {
        assert!(!permitted(&layout, &layout.session, &command), "{command}");
    }
}

#[test]
fn instruction_file_redirects_stay_reviewed_when_the_home_lies_below_a_temporary_root() {
    // A test host's home sits below `/tmp`, where the temporary-root rule for
    // redirect targets would otherwise admit any file the home holds.
    let layout = layout_at(
        PathBuf::from(format!("/tmp/hg-redirect-home-{}", std::process::id())),
        "temporary-home",
    );
    let (clone, scratch) = (layout.clone.display(), layout.scratch.display());
    for command in [
        format!("cat {scratch}/x.ts >> {clone}/AGENTS.md"),
        format!("cat {scratch}/x.ts > {clone}/AGENTS.md"),
        format!("cat > {clone}/AGENTS.md <<'EOF'\nmore rules\nEOF"),
    ] {
        assert!(!permitted(&layout, &layout.session, &command), "{command}");
    }
    let source = format!("cat {scratch}/x.ts >> {clone}/src/lib/y.ts");
    assert!(permitted(&layout, &layout.session, &source), "{source}");
}

#[test]
fn empty_git_markers_cannot_turn_plain_home_folders_into_workspaces() {
    let layout = layout("false-repository");
    let scratch = layout.scratch.display();
    for (name, directory) in [("empty-dir", true), ("empty-file", false)] {
        let folder = layout.home.join(name);
        std::fs::create_dir_all(&folder).unwrap();
        let marker = folder.join(".git");
        if directory {
            std::fs::create_dir_all(&marker).unwrap();
        } else {
            std::fs::write(&marker, "").unwrap();
        }
        let command = format!("cat {scratch}/x.ts > {}/report.ts", folder.display());
        assert!(!permitted(&layout, &layout.session, &command), "{command}");
    }
}

#[test]
fn a_home_spelled_through_a_symlinked_parent_still_writes_its_sibling_clone() {
    // The harness hands Guard the home as the session spells it. A macOS
    // temporary home is `/var/folders/...` and resolves to `/private/var/...`,
    // so comparing the resolved target with the spelled one refused every
    // write below such a home. Only the part below the home is compared now.
    let spelled = layout_spelled("spelled-home");
    let layout = &spelled.layout;
    let (clone, scratch) = (layout.clone.display(), layout.scratch.display());
    for command in [
        format!("cat {scratch}/x.ts > {clone}/src/lib/y.ts"),
        format!("cat {scratch}/x.ts >> {clone}/src/lib/auth.ts"),
        format!("cat > {clone}/notes.md <<'EOF'\n# Pending\n- a\nEOF"),
    ] {
        assert!(permitted(layout, &layout.session, &command), "{command}");
    }
}

#[test]
fn a_link_inside_a_symlink_spelled_home_is_still_refused() {
    // The screen the spelling comparison replaced kept an alias inside the
    // home from redirecting a write. It still does: a link to the clone, and
    // a link out of the clone, both keep their review.
    let spelled = layout_spelled("spelled-home-link");
    let layout = &spelled.layout;
    let alias = layout.home.join("alias");
    symlink(&layout.clone, &alias).unwrap();
    let (scratch, clone) = (layout.scratch.display(), layout.clone.display());
    for command in [
        format!("cat {scratch}/x.ts > {}/src/lib/y.ts", alias.display()),
        format!("cat {scratch}/x.ts > {clone}/src/lib/link.ts"),
        format!("cat {scratch}/x.ts > {clone}/linked/a.md"),
        format!("cat {scratch}/x.ts >> {}/.zshrc", layout.home.display()),
    ] {
        assert!(!permitted(layout, &layout.session, &command), "{command}");
    }
}
