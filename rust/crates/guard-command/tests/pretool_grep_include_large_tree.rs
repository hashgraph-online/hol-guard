//! A recursive `grep` limited by `--include` over a project folder holding a
//! few thousand generated files and a gitignored secrets file beside the
//! notes being searched.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

struct FixtureDirectory(std::path::PathBuf);

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write(path: &std::path::Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

#[test]
fn an_include_search_reads_past_a_few_thousand_generated_files() {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/grep-include-large-tree")
        .join(format!("{}-{nonce}", std::process::id()));
    let _fixture = FixtureDirectory(root.clone());
    let home = root.join("home");
    let tools = home.join("work/ads-tools");
    write(&tools.join(".gitignore"), "ads.secrets.json\n");
    write(
        &tools.join("ads.secrets.json"),
        "{\"token\": \"request GET\"}\n",
    );
    write(&tools.join("README.md"), "# Ads tools\n");
    write(&tools.join("docs/api.md"), "request GET /stats\n");
    // Generated reports: more entries than the include walk used to inspect.
    for run in 0..30 {
        let directory = tools.join(format!("output/run-{run}"));
        std::fs::create_dir_all(&directory).unwrap();
        for file in 0..100 {
            std::fs::write(directory.join(format!("shot-{file}.json")), "{}").unwrap();
        }
    }
    let home = std::fs::canonicalize(home).unwrap();
    let tools = std::fs::canonicalize(tools).unwrap();
    // Quoted so a checkout path holding a space stays one argument.
    let folder = format!("'{}'", tools.to_string_lossy().replace('\'', r"'\''"));
    for harness in ["claude-code", "codex", "omp"] {
        for (command, expected) in [
            (
                format!("grep -rn --include '*.md' 'request GET' {folder}"),
                true,
            ),
            ("grep -rn --include='*.md' 'request GET' .".to_owned(), true),
            // The secrets file is what this include selects.
            (
                format!("grep -rn --include '*.json' 'request GET' {folder}"),
                false,
            ),
            (format!("grep -rn 'request GET' {folder}"), false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
                None,
                None,
                home.to_str(),
                tools.to_str(),
            );
            assert_eq!(
                result.minimum_action == "allow",
                expected,
                "{harness}: {command}: {} {}",
                result.minimum_action,
                result.reason_code
            );
        }
    }
}
