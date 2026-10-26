#![cfg(unix)]
//! A Markdown note written directly into `~/.codex/plans` or `~/.claude/plans`
//! needs no review, through every write route: the host write tool, `cp`,
//! `touch`, and a redirect or heredoc. Everything else in a harness home
//! (configuration, hooks, rules, skills, instruction files), a hidden or
//! non-Markdown name, a subfolder, and any link or traversal keeps its review.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn fixture(name: &str) -> Fixture {
    // Avoid macOS's protected /private/var temporary root.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-plan-note-writes")
        .join(format!("{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let workspace = home.join("project");
    write(workspace.join("closeout-report.md"), "# Closeout\n");
    write(
        workspace.join("src/index.ts"),
        "export const handler = 1;\n",
    );
    write(home.join(".codex/plans/earlier-plan.md"), "# Earlier\n");
    write(home.join(".codex/hooks.json"), "{}\n");
    write(home.join(".codex/config.toml"), "model = \"synthetic\"\n");
    write(home.join(".codex/AGENTS.md"), "# Instructions\n");
    write(home.join(".codex/rules/default.md"), "# Rules\n");
    write(home.join(".codex/skills/demo/SKILL.md"), "# Skill\n");
    write(
        home.join(".codex/plans/evidence/run-1/summary.json"),
        "{}\n",
    );
    write(home.join(".claude/plans/earlier-plan.md"), "# Earlier\n");
    write(home.join(".claude/settings.json"), "{}\n");
    let root = std::fs::canonicalize(&root).unwrap();
    Fixture {
        home: root.join("home"),
        workspace: root.join("home/project"),
        root,
    }
}

fn run(f: &Fixture, harness: &str, tool: &str, input: Value) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": input}),
        None,
        None,
        f.home.to_str(),
        f.workspace.to_str(),
    )
}

fn write_tool(f: &Fixture, path: &str) -> PreToolResultV1 {
    run(
        f,
        "omp",
        "write",
        json!({"path": path, "content": "# Closeout\n- done\n"}),
    )
}

fn shell(f: &Fixture, command: &str) -> PreToolResultV1 {
    run(f, "omp", "bash", json!({ "command": command }))
}

fn allowed(result: &PreToolResultV1) -> bool {
    result.minimum_action == "allow"
}

#[test]
fn the_write_tool_files_a_note_in_a_plan_directory() {
    let f = fixture("tool-allowed");
    let home = f.home.display();
    for path in [
        format!("{home}/.codex/plans/acme-closeout.md"),
        "~/.codex/plans/acme-closeout.md".to_owned(),
        format!("{home}/.claude/plans/acme-closeout.md"),
        // An existing note is rewritten the same way.
        format!("{home}/.codex/plans/earlier-plan.md"),
    ] {
        let result = write_tool(&f, &path);
        assert!(allowed(&result), "{path}: {}", result.reason);
    }
}

#[test]
fn the_write_tool_keeps_its_review_for_everything_else_in_a_harness_home() {
    let f = fixture("tool-held");
    let home = f.home.display();
    for path in [
        format!("{home}/.codex/hooks.json"),
        format!("{home}/.codex/config.toml"),
        format!("{home}/.codex/AGENTS.md"),
        format!("{home}/.codex/notes.md"),
        format!("{home}/.codex/rules/default.md"),
        format!("{home}/.codex/rules/new-rule.md"),
        format!("{home}/.codex/skills/demo/SKILL.md"),
        format!("{home}/.codex/plans/AGENTS.md"),
        format!("{home}/.codex/plans/notes.txt"),
        format!("{home}/.codex/plans/hooks.json"),
        format!("{home}/.codex/plans/config.toml"),
        format!("{home}/.codex/plans/.hidden.md"),
        format!("{home}/.codex/plans/evidence/run-1/closeout.md"),
        format!("{home}/.codex/plans/evidence/closeout.md"),
        format!("{home}/.codex/plans/evidence/run-1/summary.json"),
        format!("{home}/.claude/settings.json"),
        format!("{home}/.claude/plans/CLAUDE.md"),
        format!("{home}/.agent/artifacts/closeout.md"),
        // Traversal out of the plan directory.
        format!("{home}/.codex/plans/../hooks.json"),
        "~/.codex/plans/../hooks.json".to_owned(),
        format!("{home}/.codex/plans/../plans/closeout.md"),
        // A look-alike folder is not a plan directory.
        format!("{home}/.codex/plan/closeout.md"),
    ] {
        let result = write_tool(&f, &path);
        assert!(!allowed(&result), "{path}");
    }
}

#[test]
fn a_link_or_second_name_never_makes_a_note_of_a_protected_file() {
    let f = fixture("tool-links");
    let home = f.home.display().to_string();
    let plans = f.home.join(".codex/plans");
    std::os::unix::fs::symlink(f.home.join(".codex/hooks.json"), plans.join("alias.md")).unwrap();
    std::os::unix::fs::symlink(plans.join("earlier-plan.md"), plans.join("second-name.md"))
        .unwrap();
    std::fs::hard_link(f.home.join(".codex/config.toml"), plans.join("twin.md")).unwrap();
    for name in ["alias.md", "second-name.md", "twin.md"] {
        let path = format!("{home}/.codex/plans/{name}");
        assert!(!allowed(&write_tool(&f, &path)), "{path}");
        assert!(
            !allowed(&shell(&f, &format!("cp closeout-report.md {path}"))),
            "{path}"
        );
        assert!(
            !allowed(&shell(&f, &format!("echo done > {path}"))),
            "{path}"
        );
    }
    // The plan directory itself a link into somewhere else.
    let f = fixture("tool-linked-directory");
    let home = f.home.display().to_string();
    std::fs::create_dir_all(f.root.join("elsewhere")).unwrap();
    std::fs::remove_dir_all(f.home.join(".claude/plans")).unwrap();
    std::os::unix::fs::symlink(f.root.join("elsewhere"), f.home.join(".claude/plans")).unwrap();
    let path = format!("{home}/.claude/plans/closeout.md");
    assert!(!allowed(&write_tool(&f, &path)), "{path}");
    assert!(
        !allowed(&shell(&f, &format!("cp closeout-report.md {path}"))),
        "{path}"
    );
    // The harness home itself a link.
    let f = fixture("tool-linked-home");
    let home = f.home.display().to_string();
    std::fs::create_dir_all(f.root.join("elsewhere/plans")).unwrap();
    std::fs::remove_dir_all(f.home.join(".codex")).unwrap();
    std::os::unix::fs::symlink(f.root.join("elsewhere"), f.home.join(".codex")).unwrap();
    let path = format!("{home}/.codex/plans/closeout.md");
    assert!(!allowed(&write_tool(&f, &path)), "{path}");
}

#[test]
fn a_missing_plan_directory_keeps_the_review() {
    let f = fixture("missing-directory");
    std::fs::remove_dir_all(f.home.join(".claude/plans")).unwrap();
    let home = f.home.display();
    assert!(!allowed(&write_tool(
        &f,
        &format!("{home}/.claude/plans/closeout.md")
    )));
    assert!(!allowed(&shell(
        &f,
        &format!("cp closeout-report.md {home}/.claude/plans/closeout.md")
    )));
}

#[test]
fn cp_and_touch_file_a_note_in_a_plan_directory() {
    let f = fixture("cp-allowed");
    let home = f.home.display();
    for command in [
        "cp closeout-report.md ~/.codex/plans/acme-closeout.md".to_owned(),
        format!("cp closeout-report.md {home}/.codex/plans/acme-closeout.md"),
        format!(
            "cp {}/closeout-report.md ~/.claude/plans/acme-closeout.md",
            f.workspace.display()
        ),
        "cp closeout-report.md ~/.codex/plans/earlier-plan.md".to_owned(),
        // A destination that is a folder takes the source's own name.
        "cp closeout-report.md ~/.codex/plans/".to_owned(),
        "cp closeout-report.md ~/.codex/plans".to_owned(),
        "touch ~/.codex/plans/acme-closeout.md".to_owned(),
    ] {
        let result = shell(&f, &command);
        assert!(allowed(&result), "{command}: {}", result.reason);
    }
}

#[test]
fn cp_and_touch_keep_their_review_for_everything_else() {
    let f = fixture("cp-held");
    for command in [
        "cp closeout-report.md ~/.codex/hooks.json",
        "cp closeout-report.md ~/.codex/config.toml",
        "cp closeout-report.md ~/.codex/AGENTS.md",
        "cp closeout-report.md ~/.codex/rules/default.md",
        "cp closeout-report.md ~/.codex/skills/demo/SKILL.md",
        "cp closeout-report.md ~/.codex/plans/AGENTS.md",
        "cp closeout-report.md ~/.codex/plans/notes.txt",
        "cp closeout-report.md ~/.codex/plans/.hidden.md",
        "cp closeout-report.md ~/.codex/plans/evidence/closeout.md",
        "cp closeout-report.md ~/.codex/plans/../hooks.json",
        "cp closeout-report.md ~/.codex/plans/evidence/",
        "cp closeout-report.md ~/.codex/rules/",
        "cp closeout-report.md ~/.codex/",
        "touch ~/.codex/hooks.json",
        "touch ~/.codex/plans/notes.txt",
        "touch ~/.codex/plans/.hidden.md",
        // Only a write that creates or fills the note is carved out; moving,
        // editing in place and deleting a note keep the generic review.
        "mv closeout-report.md ~/.codex/plans/acme-closeout.md",
        "rm ~/.codex/plans/earlier-plan.md",
        "sed -i 's/Earlier/Later/' ~/.codex/plans/earlier-plan.md",
    ] {
        let result = shell(&f, command);
        assert!(!allowed(&result), "{command}");
    }
}

#[test]
fn a_redirect_or_heredoc_files_a_note_in_a_plan_directory() {
    let f = fixture("redirect-allowed");
    let home = f.home.display();
    for command in [
        "echo done > ~/.codex/plans/acme-closeout.md".to_owned(),
        format!("echo done > {home}/.codex/plans/acme-closeout.md"),
        "echo done >> ~/.codex/plans/earlier-plan.md".to_owned(),
        "cat > ~/.codex/plans/acme-closeout.md <<'EOF'\n# Closeout\n- done\nEOF".to_owned(),
        format!("cat > {home}/.claude/plans/acme-closeout.md <<'EOF'\n# Closeout\n- done\nEOF"),
        "cat closeout-report.md > ~/.codex/plans/acme-closeout.md".to_owned(),
        // A date substitution is inert text, so the name it builds is still
        // a plain Markdown note.
        "echo done > ~/.codex/plans/$(date +%F).md".to_owned(),
    ] {
        let result = shell(&f, &command);
        assert!(allowed(&result), "{command}: {}", result.reason);
    }
}

#[test]
fn a_redirect_or_heredoc_keeps_its_review_for_everything_else() {
    let f = fixture("redirect-held");
    let home = f.home.display();
    for command in [
        "echo '{}' > ~/.codex/hooks.json".to_owned(),
        "echo '{}' >> ~/.codex/hooks.json".to_owned(),
        "echo done > ~/.codex/config.toml".to_owned(),
        "echo done > ~/.codex/AGENTS.md".to_owned(),
        "echo done > ~/.codex/rules/default.md".to_owned(),
        "echo done > ~/.codex/skills/demo/SKILL.md".to_owned(),
        "echo done > ~/.codex/plans/AGENTS.md".to_owned(),
        "echo done > ~/.codex/plans/notes.txt".to_owned(),
        "echo done > ~/.codex/plans/.hidden.md".to_owned(),
        "echo done > ~/.codex/plans/evidence/closeout.md".to_owned(),
        "echo done > ~/.codex/plans/../hooks.json".to_owned(),
        format!("echo done > {home}/.codex/plans/../hooks.json"),
        format!("echo done > {home}/.codex/hooks.json"),
        "cat > ~/.codex/hooks.json <<'EOF'\n{}\nEOF".to_owned(),
        format!("cat > {home}/.codex/hooks.json <<'EOF'\n{{}}\nEOF"),
        // Variables are not spellings Guard resolves.
        "echo done > $HOME/.codex/plans/acme-closeout.md".to_owned(),
        // A second write that is not a note keeps the whole command in review.
        "echo done > ~/.codex/plans/acme-closeout.md && echo '{}' > ~/.codex/hooks.json".to_owned(),
        "echo done > ~/.codex/plans/acme-closeout.md; rm -rf ~/.codex/rules".to_owned(),
    ] {
        let result = shell(&f, &command);
        assert!(!allowed(&result), "{command}");
    }
}

#[test]
fn an_existing_program_is_never_a_note_to_overwrite() {
    use std::os::unix::fs::PermissionsExt;

    let f = fixture("executable-note");
    let program = f.home.join(".codex/plans/tool.md");
    write(program.clone(), "#!/bin/sh\necho synthetic\n");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    let home = f.home.display();
    for command in [
        "echo done > ~/.codex/plans/tool.md".to_owned(),
        "echo done >> ~/.codex/plans/tool.md".to_owned(),
        format!("echo done > {home}/.codex/plans/tool.md"),
        "cat > ~/.codex/plans/tool.md <<'EOF'\ndone\nEOF".to_owned(),
        "cp closeout-report.md ~/.codex/plans/tool.md".to_owned(),
        "touch ~/.codex/plans/tool.md".to_owned(),
    ] {
        let result = shell(&f, &command);
        assert!(!allowed(&result), "{command}");
    }
    assert!(!allowed(&write_tool(
        &f,
        &format!("{home}/.codex/plans/tool.md")
    )));
    // Without the execute bit the same note is an ordinary one.
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(allowed(&shell(&f, "echo done > ~/.codex/plans/tool.md")));
}

#[test]
fn the_same_rule_holds_for_the_other_hosts() {
    let f = fixture("hosts");
    let home = f.home.display();
    let note = format!("{home}/.codex/plans/acme-closeout.md");
    for (harness, tool, input) in [
        (
            "zcode",
            "Write",
            json!({"file_path": note, "content": "# Closeout\n"}),
        ),
        (
            "claude-code",
            "Write",
            json!({"file_path": note, "content": "# Closeout\n"}),
        ),
    ] {
        let result = run(&f, harness, tool, input);
        assert!(allowed(&result), "{harness}: {}", result.reason);
    }
    let hooks = format!("{home}/.codex/hooks.json");
    for (harness, tool, input) in [
        (
            "zcode",
            "Write",
            json!({"file_path": hooks, "content": "{}\n"}),
        ),
        (
            "claude-code",
            "Write",
            json!({"file_path": hooks, "content": "{}\n"}),
        ),
    ] {
        assert!(!allowed(&run(&f, harness, tool, input)), "{harness}");
    }
}

/// The command-extension layer flags a write that names a harness directory as
/// a managed-configuration write. Filing a plan note is the one such write that
/// is not.
fn flags_managed_config_write(f: &Fixture, command: &str) -> bool {
    let model = guard_command::parse_command(&guard_command::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "plan-note-vector".to_owned(),
    })
    .unwrap();
    let context = guard_command::pretool::PathContext {
        home_dir: f.home.to_str(),
        cwd: f.workspace.to_str(),
        ..Default::default()
    };
    // A command the layer cannot model, such as one with a redirect, is held
    // as a whole, which is as strict as a flagged write.
    let Ok(observations) =
        guard_command::command_compatibility::compatibility_observations_with_context(
            &model, None, context,
        )
    else {
        return true;
    };
    observations
        .rule_matches
        .iter()
        .any(|matched| matched.rule_id == "command.shell-mutations.managed-config-write")
}

#[test]
fn filing_a_plan_note_is_not_a_managed_configuration_write() {
    let f = fixture("extension-note");
    let home = f.home.display();
    for command in [
        "cp closeout-report.md ~/.codex/plans/acme-closeout.md".to_owned(),
        format!("cp closeout-report.md {home}/.claude/plans/acme-closeout.md"),
        "cp closeout-report.md ~/.codex/plans/earlier-plan.md".to_owned(),
        "cp -- closeout-report.md ~/.codex/plans/acme-closeout.md".to_owned(),
        "cp closeout-report.md ~/.codex/plans/".to_owned(),
        "touch ~/.codex/plans/acme-closeout.md".to_owned(),
    ] {
        assert!(!flags_managed_config_write(&f, &command), "{command}");
    }
}

#[test]
fn every_other_write_in_a_harness_home_is_still_a_managed_configuration_write() {
    let f = fixture("extension-held");
    for command in [
        "cp closeout-report.md ~/.codex/hooks.json",
        "cp closeout-report.md ~/.codex/config.toml",
        "cp closeout-report.md ~/.codex/AGENTS.md",
        "cp closeout-report.md ~/.codex/rules/default.md",
        "cp closeout-report.md ~/.codex/plans/AGENTS.md",
        "cp closeout-report.md ~/.codex/plans/notes.txt",
        "cp closeout-report.md ~/.codex/plans/.hidden.md",
        "cp closeout-report.md ~/.codex/plans/evidence/",
        "cp closeout-report.md ~/.codex/plans/../hooks.json",
        // A source in a harness directory is a read of configuration.
        "cp ~/.codex/hooks.json ~/.codex/plans/acme-closeout.md",
        "cp ~/.codex/config.toml ~/.codex/plans/acme-closeout.md",
        // More than the one note is written, or the copy is more than a copy.
        "cp closeout-report.md ~/.codex/plans/a.md ~/.codex/hooks.json",
        "cp -r closeout-report.md ~/.codex/plans/acme-closeout.md",
        "cp closeout-report.md ~/.codex/plans/acme-closeout.md > ~/.codex/hooks.json",
        "mv closeout-report.md ~/.codex/plans/acme-closeout.md",
        "touch ~/.codex/hooks.json",
        "touch ~/.codex/plans/notes.txt",
        "touch ~/.codex/plans/acme-closeout.md ~/.codex/hooks.json",
        "sed -i 's/Earlier/Later/' ~/.codex/plans/earlier-plan.md",
    ] {
        assert!(flags_managed_config_write(&f, command), "{command}");
    }
}
