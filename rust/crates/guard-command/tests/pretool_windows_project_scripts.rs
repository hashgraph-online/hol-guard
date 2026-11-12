#![cfg(windows)]

//! A project script that only reads the workspace runs in the Windows
//! AppContainer for every harness with a sink command, Codex included: its
//! PowerShell sink names the profile, so a Node script takes the same route
//! as a Python one instead of stopping for review.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

const NODE_EVAL: &str = "native_node_eval_readonly_containment_required";
const PYTHON_EVAL: &str = "native_python_eval_readonly_containment_required";
const NODE_REPORT: &str = "import { readdirSync, readFileSync } from 'node:fs';\n\nconst files = readdirSync('src');\nconst first = readFileSync('src/one.ts', 'utf8').split('\\n')[0];\nconsole.log(`report: ${files.length} files; first line: ${first}`);\n";
const PYTHON_REPORT: &str = "from pathlib import Path\n\nfiles = list(Path(\"src\").iterdir())\nfirst = Path(\"src/one.ts\").read_text(encoding=\"utf-8\").splitlines()[0]\nprint(f\"report: {len(files)} files; first line: {first}\")\n";

/// A home below the target directory holding a project with both report
/// scripts, written with `newline` line endings.
fn project(newline: &str) -> (PathBuf, PathBuf) {
    let label = if newline == "\n" { "lf" } else { "crlf" };
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../target/windows-project-scripts/{}-{label}",
        std::process::id()
    ));
    let work = root.join("work");
    std::fs::create_dir_all(work.join("scripts")).unwrap();
    std::fs::create_dir_all(work.join("src")).unwrap();
    std::fs::write(work.join("src/one.ts"), "export const one = 1;\n").unwrap();
    std::fs::write(
        work.join("scripts/report.mjs"),
        NODE_REPORT.replace('\n', newline),
    )
    .unwrap();
    std::fs::write(
        work.join("scripts/report.py"),
        PYTHON_REPORT.replace('\n', newline),
    )
    .unwrap();
    let home = std::fs::canonicalize(&root).unwrap();
    let home = PathBuf::from(home.to_str().unwrap().trim_start_matches(r"\\?\"));
    let work = home.join("work");
    (home, work)
}

fn weighed(home: &Path, cwd: &Path, harness: &str, command: &str) -> (String, String) {
    let result = evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    );
    (result.minimum_action, result.reason_code)
}

#[test]
fn a_read_only_project_script_is_contained_for_every_sink_harness() {
    for newline in ["\n", "\r\n"] {
        let (home, work) = project(newline);
        for harness in ["codex", "claude-code", "omp"] {
            for (command, reason) in [
                ("node scripts/report.mjs", NODE_EVAL),
                ("python scripts/report.py", PYTHON_EVAL),
            ] {
                assert_eq!(
                    weighed(&home, &work, harness, command),
                    ("sandbox-required".to_string(), reason.to_string()),
                    "{harness}: {command}"
                );
            }
        }
        // Z Code has no verified Windows shell for the sink, so it keeps the
        // single review whose approval lets the retry run.
        for command in ["node scripts/report.mjs", "python scripts/report.py"] {
            assert_ne!(
                weighed(&home, &work, "zcode", command).0,
                "sandbox-required",
                "zcode: {command}"
            );
        }
        let _ = std::fs::remove_dir_all(&home);
    }
}
