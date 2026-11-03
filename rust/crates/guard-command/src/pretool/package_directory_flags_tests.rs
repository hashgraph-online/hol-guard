use super::as_cd_list;
use crate::pretool::PathContext;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("guard-pkgdir-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("web")).unwrap();
    root.canonicalize().unwrap()
}

fn projection(raw: &str, cwd: &str) -> Option<String> {
    let model = crate::parse_command(&crate::CommandModelRequestV1 {
        command: raw.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    })
    .unwrap();
    let context = PathContext {
        cwd: Some(cwd),
        ..PathContext::default()
    };
    as_cd_list(&model, context).map(|projected| projected.text)
}

/// A script run spelled without `run` is the same call as the `run` spelling,
/// so the directory flag is peeled for both.
#[test]
fn an_implicit_script_run_projects_like_the_run_spelling() {
    let root = fixture("implicit");
    let cwd = root.to_str().unwrap();
    let web = root.join("web");
    let web = web.to_str().unwrap();
    for (raw, expected) in [
        ("pnpm -C web build", format!("cd {web} && pnpm build")),
        ("pnpm --dir web build", format!("cd {web} && pnpm build")),
        ("pnpm --dir=web build", format!("cd {web} && pnpm build")),
        ("yarn --cwd web build", format!("cd {web} && yarn build")),
        ("bun --cwd web build", format!("cd {web} && bun build")),
        ("npm --prefix web build", format!("cd {web} && npm build")),
        ("npm --prefix web test", format!("cd {web} && npm test")),
        (
            "pnpm -C web run build",
            format!("cd {web} && pnpm run build"),
        ),
        (
            "pnpm --dir=web build 2>&1 | tail -20",
            format!("cd {web} && pnpm build 2>&1 | tail -20"),
        ),
    ] {
        assert_eq!(projection(raw, cwd).as_deref(), Some(&*expected), "{raw}");
    }
}

/// A registry verb or a tool runner is projected too, so the peel decides
/// nothing on its own: the rest is judged in the resolved directory exactly as
/// if it had been typed there, which is where `pnpm install` meets the package
/// checks and `npm exec vitest` meets the node-tool containment route.
#[test]
fn a_registry_verb_projects_into_the_cd_form_that_carries_its_own_verdict() {
    let root = fixture("registry");
    let cwd = root.to_str().unwrap();
    let web = root.join("web");
    let web = web.to_str().unwrap();
    for (raw, expected) in [
        ("pnpm -C web install", format!("cd {web} && pnpm install")),
        (
            "yarn --cwd web add left-pad",
            format!("cd {web} && yarn add left-pad"),
        ),
        (
            "npm --prefix web exec vitest run",
            format!("cd {web} && npm exec vitest run"),
        ),
        (
            "bun --cwd web x vite build",
            format!("cd {web} && bun x vite build"),
        ),
    ] {
        assert_eq!(projection(raw, cwd).as_deref(), Some(&*expected), "{raw}");
    }
}

/// The peel still needs one directory flag, a directory that exists and a
/// rest to run.
#[test]
fn other_shapes_keep_the_unprojected_text() {
    let root = fixture("unprojected");
    let cwd = root.to_str().unwrap();
    for raw in [
        "pnpm build",
        "pnpm -C web",
        "pnpm -C missing build",
        "pnpm -C web -C other build",
        "cargo -C web build",
    ] {
        assert_eq!(projection(raw, cwd), None, "{raw}");
    }
}

/// A directory the flag reaches by climbing out of the run's own is projected
/// like any other that exists. The peel compares nothing with the workspace:
/// it only rewrites the call into the `cd` form, and whether that directory
/// may be entered at all is the containment check's answer, read from the
/// projected text. Pinning this keeps the two apart, so a later change that
/// quietly refused such a path here would show up as a failure rather than as
/// a bound nobody wrote down.
#[test]
fn a_directory_above_the_run_projects_and_leaves_the_bound_to_containment() {
    let root = fixture("above");
    let outside = root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let cwd = root.join("web");
    let expected = format!("cd {} && pnpm build", outside.to_str().unwrap());
    assert_eq!(
        projection("pnpm -C ../outside build", cwd.to_str().unwrap()).as_deref(),
        Some(&*expected)
    );
}

/// A workspace fixture: a root holding `pnpm-workspace.yaml` and a package
/// below it, which is where `pnpm -w` is typed from.
fn workspace(name: &str) -> PathBuf {
    let root = fixture(name);
    std::fs::write(root.join("pnpm-workspace.yaml"), "packages:\n  - web\n").unwrap();
    root
}

/// `pnpm -w <rest>` runs the rest in the workspace root, so it is the same
/// call as `cd <root> && pnpm <rest>` and reaches containment the way the
/// spelled directory and the typed `cd` already do. Without this the root
/// script of every pnpm monorepo was a review prompt while the same script
/// run without the flag was contained silently.
#[test]
fn the_workspace_root_flag_projects_like_a_spelled_directory() {
    let root = workspace("workspace-root");
    let cwd = root.to_str().unwrap();
    for (raw, expected) in [
        ("pnpm -w run build", format!("cd {cwd} && pnpm run build")),
        (
            "pnpm --workspace-root run build",
            format!("cd {cwd} && pnpm run build"),
        ),
        ("pnpm -w build", format!("cd {cwd} && pnpm build")),
        ("pnpm run -w build", format!("cd {cwd} && pnpm run build")),
        ("pnpm -w test", format!("cd {cwd} && pnpm test")),
        (
            "pnpm -w add left-pad",
            format!("cd {cwd} && pnpm add left-pad"),
        ),
        (
            "pnpm -w run build 2>&1 | tail -20",
            format!("cd {cwd} && pnpm run build 2>&1 | tail -20"),
        ),
    ] {
        assert_eq!(projection(raw, cwd).as_deref(), Some(&*expected), "{raw}");
    }
}

/// The root is found the way pnpm finds it, by climbing from the directory
/// the command was typed in. As with a spelled directory, the peel says
/// nothing about whether that root may be entered: the projected text carries
/// that to the containment check, which is what keeps a package's own
/// sandbox from being widened to its monorepo by a flag.
#[test]
fn the_workspace_root_is_found_by_climbing_out_of_the_run_directory() {
    let root = workspace("workspace-climb");
    let cwd = root.join("web");
    let expected = format!("cd {} && pnpm run build", root.to_str().unwrap());
    assert_eq!(
        projection("pnpm -w run build", cwd.to_str().unwrap()).as_deref(),
        Some(&*expected)
    );
}

/// The flag is read in its two exact spellings only, for pnpm alone, and
/// needs a workspace to name. npm's `-w` takes a workspace *name* rather than
/// naming the root, so reading it as this flag would drop a word the run
/// depends on.
#[test]
fn other_workspace_root_spellings_keep_the_unprojected_text() {
    let root = workspace("workspace-other");
    let cwd = root.to_str().unwrap();
    for raw in [
        "pnpm -w",
        "pnpm -wx run build",
        "pnpm --workspace-root=web run build",
        "pnpm -w -C web run build",
        "pnpm -w --workspace-root run build",
        "npm -w web run build",
        "yarn -w run build",
        "bun -w run build",
    ] {
        assert_eq!(projection(raw, cwd), None, "{raw}");
    }
    let bare = fixture("workspace-none");
    assert_eq!(
        projection("pnpm -w run build", bare.to_str().unwrap()),
        None
    );
}
