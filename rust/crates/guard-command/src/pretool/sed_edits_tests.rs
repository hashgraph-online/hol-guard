// The filesystem cases below need symlinks and an executable bit.
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use super::append_scripts::inert_text_insert;
use super::{in_place_edit, in_place_edit_with, inert_substitution, proven_in_place_segment};
use crate::native_command_controls::CompiledNativeCommandControls;
use crate::native_command_program::packaged_command_program;
use crate::pretool::PathContext;
use guard_contracts::NativeCommandControlBindingV1;
use std::path::{Path, PathBuf};

struct Layout {
    root: PathBuf,
    home: String,
    workspace: String,
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// A home directory holding `app-portal`, plus files outside both.
fn layout(name: &str) -> Layout {
    let root = std::env::temp_dir().join(format!("guard-sed-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let workspace = home.join("app-portal");
    let page = "export default function Page() {\n  return <a href={OLD}>Home</a>;\n}\n";
    write(&workspace.join("src/app/page.tsx"), page);
    write(&workspace.join("src/index.ts"), "export const a = 1;\n");
    write(&workspace.join("docs/agents.md"), "# notes\n");
    write(&workspace.join("AGENTS.md"), "# agents\n");
    write(&workspace.join("CLAUDE.md"), "# claude\n");
    write(&workspace.join(".env"), "PORT=3000\n");
    write(&workspace.join(".git/config"), "[core]\n\tbare = false\n");
    write(&workspace.join(".github/workflows/ci.yml"), "on: push\n");
    write(&workspace.join(".husky/pre-commit"), "npm test\n");
    write(&workspace.join("deploy.sh"), "echo deploy\n");
    write(&workspace.join("tools/deploy.ps1"), "Write-Host deploy\n");
    write(&workspace.join("deploy"), "echo deploy\n");
    write(&workspace.join("notes/AGENTS"), "# agents\n");
    write(&workspace.join("src/linked"), "a\n");
    write(&home.join("notes.txt"), "a\n");
    write(&root.join("outside/file.ts"), "a\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let script = workspace.join("deploy.sh");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(
            root.join("outside/file.ts"),
            workspace.join("src/linked.ts"),
        )
        .unwrap();
        std::os::unix::fs::symlink(root.join("outside"), workspace.join("vendor")).unwrap();
    }
    let canonical = |path: PathBuf| path.canonicalize().unwrap().to_str().unwrap().to_owned();
    Layout {
        home: canonical(home),
        workspace: canonical(workspace),
        root: root.canonicalize().unwrap(),
    }
}

fn model(command: &str) -> crate::CanonicalCommandV1 {
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap()
}

fn proven_in(layout: &Layout, cwd: &str, command: &str) -> bool {
    let model = model(command);
    let context = PathContext {
        home_dir: Some(layout.home.as_str()),
        cwd: Some(cwd),
        ..PathContext::default()
    };
    model.confidence == "exact"
        && model
            .segments
            .iter()
            .any(|segment| proven_in_place_segment(&model, segment, context))
}

fn proven(layout: &Layout, command: &str) -> bool {
    proven_in(layout, &layout.workspace, command)
}

fn words(command: &str) -> Vec<String> {
    command.split(' ').map(str::to_owned).collect()
}

#[test]
fn single_substitutions_are_inert() {
    for script in [
        "s|href={OLD}|href={next}|",
        "s/OLD/next/g",
        "s#a#b#",
        r"s/a\/b/c/",
        r"s/\(foo\)/\1bar/g",
        "s/[[:space:]]*$//",
        "s|[]a]|b|",
        "s|[^]a]|b|g",
        "s/x/&&/",
    ] {
        assert!(inert_substitution(script), "{script}");
    }
    for script in [
        "s/a/b/e",
        "s|24h|7d|e",
        "s#a#b#e",
        "s/a/b/ge",
        "s/a/b/eg",
        "s/a/b/gw out.txt",
        "s/a/b/eI",
        "s/a/b/Me",
        "s/a/b/gM",
        "s/a/b/w out.txt",
        "s/a/b/;w out.txt",
        "s/a/b/;e id",
        "s/a/b/p",
        "s/a/b/gI",
        "s/a/b/ ",
        "s/a/b",
        "s/a/b/c/",
        "s/[/]/x/",
        "s|[[:alpha|:]]|x|",
        "s/[a/b/",
        "s/a/b\\",
        "s\na\nb\n",
        "s a b ",
        "sxaxbx",
        "y/ab/cd/",
        "1d",
        "e id",
        "r /etc/hosts",
        "w out.txt",
        "W out.txt",
        "R list.txt",
        "",
    ] {
        assert!(!inert_substitution(script), "{script:?}");
    }
}

#[test]
fn bsd_and_gnu_safe_spellings_are_parsed() {
    for (arguments, targets) in [
        (vec!["-i", "", "s/a/b/", "F"], 1),
        (vec!["-i", "", "-E", "s/a+/b/", "F", "G"], 2),
        (vec!["-E", "-i", "", "s/a+/b/", "F"], 1),
        (vec!["-i", "", "-e", "s/a/b/", "-e", "s/c/d/g", "F"], 1),
        (vec!["-i", "-e", "s/a/b/", "F"], 1),
        (vec!["-i", "-E", "-e", "s/a/b/", "F"], 1),
        (vec!["-i.bak", "s/a/b/", "F"], 1),
        (
            vec!["-E", "-i~", "-e", "s/a/b/", "-e", "s/c/d/", "F", "G"],
            2,
        ),
    ] {
        let arguments: Vec<String> = arguments.into_iter().map(str::to_owned).collect();
        let parsed = in_place_edit(&arguments).map(|edit| edit.targets.len());
        assert_eq!(parsed, Some(targets), "{arguments:?}");
    }
    let suffix = |command: &str| {
        let arguments = words(command);
        in_place_edit(&arguments).and_then(|edit| edit.backup_suffix.map(str::to_owned))
    };
    assert_eq!(suffix("-i.bak s/a/b/ F").as_deref(), Some(".bak"));
    assert_eq!(suffix("-i~ -e s/a/b/ -e s/c/d/ F G").as_deref(), Some("~"));
    assert_eq!(suffix("-i -e s/a/b/ F").as_deref(), Some("-e"));
    assert_eq!(suffix("-i -E -e s/a/b/ F").as_deref(), Some("-E"));
    // BSD sed reads the script as a backup suffix in the GNU operand form.
    let gnu = words("-i s/a/b/ F");
    assert_eq!(in_place_edit(&gnu).is_some(), cfg!(target_os = "linux"));
    for command in [
        "-i.b/k s/a/b/ F",
        "-i*.bak s/a/b/ F",
        "-i.bakbakbakbakbakbak s/a/b/ F",
        "--in-place s/a/b/ F",
        "-n -i s/a/b/p F",
        "-i -n s/a/b/p F",
        "-i -s s/a/b/ F",
        "-i -z s/a/b/ F",
        "-i -r s/a/b/ F",
        "-i --follow-symlinks s/a/b/ F",
        "-i -f edits.sed F",
        "-i -e s/a/b/ -e s/c/d/ F",
        "-i -e s/a/b/",
        "-i -e s/a/b/ -- F",
        "-i -e s/a/b/ -F",
        "-i -e s/a/b/e F",
        "s/a/b/ F",
    ] {
        assert!(in_place_edit(&words(command)).is_none(), "{command}");
    }
    for arguments in [
        vec!["-i", "", "s/a/b/"],
        vec!["-i", "", "s/a/b/", ""],
        // GNU sed would rewrite `s/../../g` as a file outside the directory.
        vec!["-i", "", "s/../../g", "F"],
        vec!["-i", "", "-n", "s/a/b/p", "F"],
    ] {
        let arguments: Vec<String> = arguments.into_iter().map(str::to_owned).collect();
        assert!(in_place_edit(&arguments).is_none(), "{arguments:?}");
    }
    let many: Vec<String> = ["-i", "", "s/a/b/"]
        .into_iter()
        .map(str::to_owned)
        .chain((0..17).map(|index| format!("f{index}")))
        .collect();
    assert!(in_place_edit(&many).is_none());
}

#[test]
fn line_inserts_are_one_address_and_literal_text() {
    for script in [
        "/export const a/a\\\nexport const b = 2;",
        "/x/i\\\nfirst",
        "12a\\\nline",
        "3i\\inline text",
        "/x/a\\\nline one\\\nline two",
        // A command letter inside the text is text, not a command.
        "/x/a\\\nw /tmp/out.txt",
        "/a\\/b/a\\\nx",
    ] {
        assert!(inert_text_insert(script), "{script:?}");
    }
    for script in [
        // An unescaped newline ends the text and starts a new command.
        "/x/a\\\ntext\nw /tmp/out.txt",
        "/x/a\\\ntext\ne echo hi",
        "/x/a\\\n\nw /tmp/out.txt",
        // Other commands, flags, ranges, negation and custom delimiters.
        "/x/c\\\ntext",
        "/x/d",
        "/x/!a\\\ntext",
        "/x/Ia\\\ntext",
        "1,3a\\\ntext",
        "$a\\\ntext",
        "\\|x|a\\\ntext",
        "a\\\ntext",
        "/x/ a\\\ntext",
        "/x/a text",
        // A bracket expression that holds the delimiter, an address that
        // never closes, and text that is missing or ends in a backslash.
        "/[/]/a\\\ntext",
        "/[^]/]/a\\\ntext",
        "/x\\/a\\\ntext",
        "/x/a\\",
        "/x/a\\\n",
        "/x/a\\\ntext\\",
        "/x/a\\\ntext\r",
        "/x/a\\\ntext\0",
        "0123456789a\\\ntext",
    ] {
        assert!(!inert_text_insert(script), "{script:?}");
    }
}

#[test]
fn only_a_scratch_edit_may_insert_a_line() {
    let insert = |script: &str| {
        vec![
            "-i".to_owned(),
            String::new(),
            script.to_owned(),
            "/tmp/x.ts".to_owned(),
        ]
    };
    let line = insert("12a\\\ntext");
    assert!(in_place_edit(&line).is_none());
    assert_eq!(
        in_place_edit_with(&line, true).map(|e| e.targets.len()),
        Some(1)
    );
    let substitution = insert("s/a/b/");
    assert!(in_place_edit(&substitution).is_some());
    assert!(in_place_edit_with(&substitution, true).is_some());
    // GNU sed reads `-i '' /pat/...` as a file named `/pat/...`, which only
    // BSD sed (the macOS default) takes for the script.
    let address = insert("/x/a\\\ntext");
    assert_eq!(
        in_place_edit_with(&address, true).is_some(),
        cfg!(target_os = "macos")
    );
    // A script that mixes an insert with another command stays reviewed.
    let mixed = ["-i", "", "-e", "12a\\\ntext", "-e", "s/a/b/e", "/tmp/x.ts"].map(str::to_owned);
    assert!(in_place_edit_with(&mixed, true).is_none());
}

#[cfg(unix)]
#[test]
fn ordinary_workspace_files_are_edited_in_place() {
    let layout = layout("admitted");
    let workspace = &layout.workspace;
    for command in [
        "sed -i '' 's|href={OLD}|href={next}|' src/app/page.tsx".to_owned(),
        "sed -i '' -e 's/OLD/next/g' src/app/page.tsx".to_owned(),
        "sed -i '' -e 's/a/b/' -e 's/c/d/g' src/app/page.tsx src/index.ts".to_owned(),
        "sed -E -i '' 's/(OLD)+/next/' ./src/app/page.tsx".to_owned(),
        "sed -i '' -E 's#OLD#next#g' src/app/page.tsx 2>&1".to_owned(),
        "sed -i -e 's/OLD/next/' src/app/page.tsx".to_owned(),
        "sed -i.bak 's/OLD/next/' src/app/page.tsx".to_owned(),
        "sed -i.orig -e 's/OLD/next/' src/index.ts".to_owned(),
        "sed -i '' 's/[[:space:]]*$//' src/index.ts && cat src/index.ts".to_owned(),
        format!("sed -i '' 's/OLD/next/' {workspace}/src/app/page.tsx"),
    ] {
        assert!(proven(&layout, &command), "{command}");
    }
    let gnu = "sed -i 's/OLD/next/' src/app/page.tsx";
    assert_eq!(proven(&layout, gnu), cfg!(target_os = "linux"));
    let _ = std::fs::remove_dir_all(&layout.root);
}

#[cfg(unix)]
#[test]
fn protected_outside_and_linked_targets_stay_reviewed() {
    let layout = layout("refused");
    let home = layout.home.clone();
    let mut commands: Vec<String> = [
        ".git/config",
        ".github/workflows/ci.yml",
        ".husky/pre-commit",
        "AGENTS.md",
        "CLAUDE.md",
        "docs/agents.md",
        ".env",
        "../notes.txt",
        "~/notes.txt",
        "deploy.sh",
        "missing.ts",
        "src",
        "src/linked.ts",
        "vendor/file.ts",
        "src/app/page.tsx .git/config",
    ]
    .iter()
    .map(|target| format!("sed -i '' 's/a/b/' {target}"))
    .collect();
    commands.extend([
        format!("sed -i '' 's/a/b/' {home}/notes.txt"),
        "sed -i '' 's/a/b/' /opt/guard-outside/file.ts".to_owned(),
        "sed -i '' 's/a/b/e' src/app/page.tsx".to_owned(),
        "sed -i '' 's/a/b/w src/out.txt' src/app/page.tsx".to_owned(),
        "sed -i '' 's/a/b/;w src/out.txt' src/app/page.tsx".to_owned(),
        "sed -i '' '1r /etc/hosts' src/app/page.tsx".to_owned(),
        "sed -i '' \"s/a/$USER/\" src/app/page.tsx".to_owned(),
        "sed -i '' \"s/a/\\\\$USER/\" src/app/page.tsx".to_owned(),
        "sed -i '' $'s#a#b\\x23e\\x0a#' src/app/page.tsx".to_owned(),
        "sed -i '' 's/a/`id`/' src/app/page.tsx".to_owned(),
        "sed -i '' 's/$HOME/x/' src/app/page.tsx".to_owned(),
        "sed -i.md 's/a/b/' notes/AGENTS".to_owned(),
        "sed -i.ts 's/a/b/' src/linked".to_owned(),
        "sed -i.sh 's/a/b/' deploy".to_owned(),
        "cat src/index.ts | sed -i '' 's/a/b/' src/app/page.tsx".to_owned(),
        "cd src && sed -i '' 's/a/b/' app/page.tsx".to_owned(),
        "mv src/linked.ts src/other.ts && sed -i '' 's/a/b/' src/other.ts".to_owned(),
        "ln -sf ../deploy.sh src/index.ts; sed -i '' 's/a/b/' src/index.ts".to_owned(),
        "git checkout feature && sed -i '' 's/a/b/' src/index.ts".to_owned(),
        "FOO=1 sed -i '' 's/a/b/' src/index.ts".to_owned(),
    ]);
    for command in &commands {
        assert!(!proven(&layout, command), "{command}");
    }
    // A home-rooted session has no workspace boundary narrower than the home.
    let command = "sed -i '' 's/a/b/' notes.txt";
    assert!(!proven_in(&layout, &home, command), "{command}");
    let _ = std::fs::remove_dir_all(&layout.root);
}

fn controls() -> CompiledNativeCommandControls {
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest, "health": "protected",
        "revision": 1, "managed_revision": 0, "effective_digest": "", "layers": []
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    CompiledNativeCommandControls::new(&binding).unwrap()
}

#[cfg(unix)]
#[test]
fn a_bounded_workspace_edit_needs_no_prompt() {
    let layout = layout("envelope");
    let controls = controls();
    let action = |harness: &str, command: &str| {
        crate::pretool::evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
            Some(&controls),
            None,
            Some(layout.home.as_str()),
            Some(layout.workspace.as_str()),
        )
    };
    for harness in ["codex", "claude-code", "omp"] {
        let edit = "sed -i '' 's|href={OLD}|href={next}|' src/app/page.tsx";
        assert_eq!(
            action(harness, edit).minimum_action,
            "allow",
            "{harness}: {edit}"
        );
        // These may still run in the workspace sandbox, but never as a proven
        // exact-safe edit on the host.
        for command in [
            "sed -i '' 's/a/b/' AGENTS.md",
            "sed -i '' 's/a/b/' .git/config",
            "sed -i '' 's/a/b/' .env",
            "sed -i '' 's/a/b/e' src/app/page.tsx",
            "sed -i '' 's|24h|7d|e' src/app/page.tsx",
            "sed -i '' 's#a#b#ge' src/app/page.tsx",
            "sed -i '' 's/a/b/gw out.txt' src/app/page.tsx",
            "sed -i '' 's/a/b/' ../notes.txt",
        ] {
            let result = action(harness, command);
            assert_ne!(result.minimum_action, "allow", "{harness}: {command}");
            assert_ne!(
                result.reason_code, "native_exact_safe_command",
                "{harness}: {command}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&layout.root);
}

#[test]
fn windows_executability_is_read_off_the_extension() {
    for name in [
        "deploy.ps1",
        "module.psm1",
        "setup.bat",
        "setup.CMD",
        "tool.exe",
        "tool.COM",
        "install.msi",
        "saver.scr",
        "legacy.vbs",
        "legacy.vbe",
        "job.wsf",
        "host.wsh",
        "legacy.jse",
        "panel.cpl",
        "console.msc",
    ] {
        assert!(super::executable_extension(Path::new(name)), "{name}");
    }
    // Win32 drops trailing dots and spaces, so these open the same programs.
    for name in ["deploy.ps1.", "deploy.ps1 ", "tool.exe...", "setup.CMD. "] {
        assert!(super::executable_extension(Path::new(name)), "{name}");
    }
    // Ordinary repository source, including the `.js` that is in `PATHEXT`.
    for name in [
        "index.ts",
        "page.tsx",
        "app.js",
        "deploy.sh",
        "notes.md",
        "deploy",
        "a.ps1.ts",
    ] {
        assert!(!super::executable_extension(Path::new(name)), "{name}");
    }
}

#[cfg(windows)]
#[test]
fn windows_in_place_edits_of_runnable_files_stay_reviewed() {
    let layout = layout("windows-executable");
    assert!(
        proven(&layout, "sed -i '' 's/a/b/' src/index.ts"),
        "an ordinary source edit has to stay silent"
    );
    assert!(
        !proven(&layout, "sed -i '' 's/deploy/ship/' tools/deploy.ps1"),
        "rewriting a file Windows runs on launch has to be reviewed"
    );
    let _ = std::fs::remove_dir_all(&layout.root);
}

/// `tools/deploy.ps1.` opens `tools/deploy.ps1`, so the edit route has to read
/// it as the program it rewrites rather than as an extensionless file.
#[cfg(windows)]
#[test]
fn a_trailing_dot_does_not_hide_a_runnable_file_from_the_edit_route() {
    let layout = layout("windows-trailing-dot");
    assert!(
        !proven(&layout, "sed -i '' 's/deploy/ship/' tools/deploy.ps1."),
        "a trailing dot opens the same program and has to be reviewed"
    );
    let _ = std::fs::remove_dir_all(&layout.root);
}
