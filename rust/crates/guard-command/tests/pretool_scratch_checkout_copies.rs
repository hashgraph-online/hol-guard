#![cfg(unix)]

//! An agent working in a workspace often keeps a scratch checkout of another
//! repository in a private temporary directory. Copying readable files from
//! it into the workspace, creating the destination directory first, and
//! checking whether a package bin is installed there are ordinary work.
//! Protected destinations, sensitive sources, link tricks and directories a
//! chain creates under a file-shaped destination stay reviewed.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
    scratch: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

/// Home and the workspace stay outside the temporary roots. The scratch
/// checkout sits in a private directory directly under `/tmp`.
fn fixture(name: &str) -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-scratch-checkout")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let project = home.join("app-portal");
    write(&project.join("src/index.ts"), "export const a = 1;\n");
    std::fs::create_dir_all(project.join(".git/hooks")).unwrap();
    write(&project.join("node_modules/.bin/tsc"), "#!/bin/sh\n");
    write(&home.join(".ssh/id_ed25519"), "synthetic key\n");
    write(&home.join(".zshrc"), "# synthetic\n");
    std::fs::create_dir_all(project.join("linked")).unwrap();
    symlink(home.join(".zshrc"), project.join("linked/README.md")).unwrap();

    let scratch = PathBuf::from(format!(
        "/tmp/hg-scratch-checkout-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir(&scratch).unwrap();
    std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700)).unwrap();
    let app = scratch.join("app");
    write(&app.join("README.md"), "# app\n");
    write(&app.join("package.json"), "{\"name\": \"app\"}\n");
    write(&app.join("src/index.ts"), "export const b = 1;\n");
    write(&app.join("src/rank.ts"), "export const rank = 1;\n");
    write(
        &app.join("tests/rank.test.ts"),
        "export const covered = 1;\n",
    );
    write(&app.join("tsconfig.json"), "{\"compilerOptions\": {}}\n");
    write(&app.join(".env"), "TOKEN=synthetic\n");
    symlink(home.join(".ssh/id_ed25519"), app.join("notes.md")).unwrap();
    let installed = scratch.join("installed");
    write(
        &installed.join("node_modules/vitest/vitest.mjs"),
        "export {};\n",
    );
    std::fs::create_dir_all(installed.join("node_modules/.bin")).unwrap();
    symlink(
        "../vitest/vitest.mjs",
        installed.join("node_modules/.bin/vitest"),
    )
    .unwrap();
    write(&installed.join("node_modules/.bin/eslint"), "#!/bin/sh\n");
    symlink(
        home.join(".ssh/id_ed25519"),
        installed.join("node_modules/.bin/key"),
    )
    .unwrap();
    let redirected = scratch.join("redirected");
    std::fs::create_dir_all(redirected.join("node_modules")).unwrap();
    symlink(home.join(".ssh"), redirected.join("node_modules/.bin")).unwrap();
    Fixture {
        home: std::fs::canonicalize(&home).unwrap(),
        project: std::fs::canonicalize(&project).unwrap(),
        root,
        scratch,
    }
}

fn permitted(fixture: &Fixture, command: &str) -> bool {
    let evaluate = |harness| {
        let result = evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"toolName": "Bash", "toolInput": {"command": command}}),
            None,
            None,
            fixture.home.to_str(),
            fixture.project.to_str(),
        );
        result.decision == "allow" && matches!(result.minimum_action.as_str(), "allow" | "warn")
    };
    let zcode = evaluate("zcode");
    assert_eq!(zcode, evaluate("omp"), "host policy drift: {command}");
    zcode
}

#[test]
fn scratch_checkout_files_copy_into_the_workspace() {
    let fixture = fixture("copies");
    let app = fixture.scratch.join("app");
    let app = app.display();
    let project = fixture.project.display();
    for command in [
        format!("cp {app}/README.md {app}/package.json {project}/src/"),
        format!("cp -- {app}/README.md {app}/src/index.ts {project}/src"),
        format!("cp {app}/README.md {app}/package.json src/"),
        format!("cp {app}/README.md {project}/src/notes/"),
        format!(
            "mkdir -p {project}/src/lib/discovery && cp {app}/README.md {project}/src/lib/discovery/"
        ),
        format!("mkdir -p src/lib/notes && cp {app}/README.md {app}/package.json src/lib/notes"),
        format!("mkdir -p src/lib && cp {app}/README.md src/lib/README.md"),
        format!("mkdir -p src/lib/notes && cp {app}/README.md src/lib/notes/README.md"),
    ] {
        assert!(permitted(&fixture, &command), "{command}");
    }
}

#[test]
fn scratch_checkout_copies_keep_source_and_destination_screens() {
    let fixture = fixture("copies-reviewed");
    let app = fixture.scratch.join("app");
    let app = app.display();
    let project = fixture.project.display();
    let home = fixture.home.display();
    for command in [
        // Hook, dotfile and credential destinations.
        format!("cp {app}/README.md {project}/.git/hooks/pre-commit"),
        format!("cp {app}/README.md {app}/package.json {project}/.git/hooks/"),
        format!("cp {app}/README.md {home}/.ssh/authorized_keys"),
        format!("cp {app}/README.md {app}/package.json {home}/.ssh/"),
        format!("cp {app}/README.md {project}/node_modules/.bin/"),
        // A destination name that is already a link out of the workspace.
        format!("cp {app}/README.md {app}/package.json {project}/linked/"),
        // Sensitive, hidden or linked sources, alone or among readable ones.
        format!("cp {home}/.ssh/id_ed25519 {project}/src/"),
        format!("cp {app}/README.md {home}/.ssh/id_ed25519 {project}/src/"),
        format!("cp {app}/README.md {app}/.env {project}/src/"),
        format!("cp {app}/notes.md {app}/README.md {project}/src/"),
        format!("mkdir -p src/out && cp {app}/.env src/out/"),
        // A directory the chain creates where the proof saw a file name.
        format!("mkdir -p src/out && cp {app}/README.md src/out"),
        format!("mkdir -p src/out/deep && cp {app}/README.md src/out"),
        // Names a case- or normalization-insensitive volume treats as equal:
        // the copy would land inside the created directory, unscreened.
        format!("mkdir -p src/Sub && cp {app}/README.md src/sub"),
        format!("mkdir -p src/Sub/deep && cp {app}/README.md src/sub"),
        format!("mkdir -p src/caf\u{e9} && cp {app}/README.md src/cafe\u{301}"),
        // A directory elsewhere in the tree keeps a file-shaped copy reviewed.
        format!("mkdir -p build/out && cp {app}/README.md src/README.md"),
        // Flags, and peers that move, link, remove or change directory.
        format!("mkdir -p src/out && cp -R {app}/src src/out/"),
        format!("mkdir -p src/out && mv {app}/README.md src/out/"),
        format!("mkdir -p src/out && ln -s {app}/README.md src/out/readme"),
        format!("mkdir -p src/out && rm -rf {app}"),
        // Workspace-to-workspace copies in a plain chain are unchanged.
        "cp src/index.ts src/e.ts && echo done".to_owned(),
    ] {
        assert!(!permitted(&fixture, &command), "{command}");
    }
}

/// `cp saved/src/*.ts dir/` is the explicit list the shell expands it to, so
/// every match gets the source screens and lands at `dir/<name>` under the
/// destination screens of a literal multi-file copy.
#[test]
fn scratch_checkout_globs_copy_like_their_expansion() {
    let fixture = fixture("glob-copies");
    let app = fixture.scratch.join("app");
    let app = app.display();
    let project = fixture.project.display();
    for command in [
        format!("cp {app}/src/*.ts {project}/src/"),
        format!("cp {app}/*.json src/"),
        format!(
            "mkdir -p {project}/src/lib/discovery && cp {app}/src/*.ts {project}/src/lib/discovery/ && cp {app}/tests/rank.test.ts {project}/src/ && echo copied"
        ),
        format!("mkdir -p src/lib/rank && cp {app}/src/r?nk.ts {app}/README.md src/lib/rank/"),
    ] {
        assert!(permitted(&fixture, &command), "{command}");
    }
}

#[test]
fn scratch_checkout_globs_keep_every_screen() {
    let fixture = fixture("glob-copies-reviewed");
    let app = fixture.scratch.join("app");
    let app = app.display();
    let project = fixture.project.display();
    let home = fixture.home.display();
    for command in [
        // A match that links to a credential, a hidden match, a directory.
        format!("cp {app}/*.md {project}/src/"),
        format!("cp {app}/* {project}/src/"),
        format!("cp {app}/s* {project}/src/"),
        // Hook, credential and package-bin destinations.
        format!("cp {app}/src/*.ts {project}/.git/hooks/"),
        format!("cp {app}/src/*.ts {home}/.ssh/"),
        format!("cp {app}/src/*.ts {project}/node_modules/.bin/"),
        // Nothing matches, the pattern is in a directory, or uses brackets.
        format!("cp {app}/src/*.missing {project}/src/"),
        format!("cp {app}/s*/index.ts {project}/src/"),
        format!("cp {app}/src/[ir]*.ts {project}/src/"),
        format!("cp {app}/src/**/*.ts {project}/src/"),
        // A directory the chain creates where the proof saw one operand.
        format!("mkdir -p src/out && cp {app}/src/*.ts src/out"),
        // Flags and moves are unchanged.
        format!("cp -f {app}/src/*.ts {project}/src/"),
        format!("mkdir -p src/out && mv {app}/src/*.ts src/out/"),
    ] {
        assert!(!permitted(&fixture, &command), "{command}");
    }
}

/// The glob model ignores case, so it can see more matches than the shell
/// passes. With one real match, `cp` writes the destination path itself.
#[test]
fn glob_copies_into_a_new_path_stay_reviewed() {
    let fixture = fixture("glob-copies-new-path");
    let app = fixture.scratch.join("app");
    write(&app.join("src/RANKED.TS"), "export const ranked = 1;\n");
    let app = app.display();
    let project = fixture.project.display();
    for command in [
        format!("cp {app}/src/r*.ts {project}/ranked"),
        format!("cp {app}/src/r*.ts src/ranked.ts"),
        format!("cp {app}/src/*.ts {project}/fresh"),
    ] {
        assert!(!permitted(&fixture, &command), "{command}");
    }
    // A trailing slash or an existing directory still copies every match in.
    for command in [
        format!("cp {app}/src/r*.ts {project}/src/"),
        format!("cp {app}/src/r*.ts {project}/src"),
    ] {
        assert!(permitted(&fixture, &command), "{command}");
    }
}

#[test]
fn scratch_checkout_package_bins_list() {
    let fixture = fixture("bins");
    let app = fixture.scratch.join("app");
    let app = app.display();
    let installed = fixture.scratch.join("installed");
    let installed = installed.display();
    for command in [
        format!("ls {app}/node_modules/.bin/vitest 2>&1 | head -1"),
        format!("ls {app}/node_modules/.bin"),
        format!("ls -la {installed}/node_modules/.bin/vitest"),
        format!("ls {installed}/node_modules/.bin/eslint"),
        format!("ls {installed}/node_modules/.bin"),
    ] {
        assert!(permitted(&fixture, &command), "{command}");
    }
}

#[test]
fn package_bin_listings_keep_link_and_credential_screens() {
    let fixture = fixture("bins-reviewed");
    let installed = fixture.scratch.join("installed");
    let installed = installed.display();
    let redirected = fixture.scratch.join("redirected");
    let redirected = redirected.display();
    let home = fixture.home.display();
    for command in [
        // A leaf that links to a credential.
        format!("ls -L {installed}/node_modules/.bin/key"),
        // A `.bin` that is a link elsewhere, and a protected root.
        format!("ls {redirected}/node_modules/.bin"),
        format!("ls {redirected}/node_modules/.bin/id_ed25519"),
        format!("ls {home}/.ssh/node_modules/.bin/vitest"),
        // Hidden and credential-shaped names.
        format!("ls {installed}/node_modules/.bin/.env"),
        format!("ls {installed}/node_modules/.bin/id_rsa"),
    ] {
        assert!(!permitted(&fixture, &command), "{command}");
    }
}

/// `tsc --noEmit` still writes `.tsbuildinfo` when the project config sets
/// `incremental` or `composite`, and `tsBuildInfoFile` can point anywhere. A
/// project config from a scratch checkout is untrusted, so the run stays
/// reviewed even with a workspace-installed compiler.
#[test]
fn typescript_runs_against_a_scratch_project_stay_reviewed() {
    let fixture = fixture("tsc");
    let app = fixture.scratch.join("app");
    let app = app.display();
    let project = fixture.project.display();
    for command in [
        format!("{project}/node_modules/.bin/tsc --noEmit -p {app}/tsconfig.json 2>&1 | head"),
        format!("{project}/node_modules/.bin/tsc --noEmit -p {app}"),
    ] {
        assert!(!permitted(&fixture, &command), "{command}");
    }
}
