#![cfg(unix)]

//! A loop or a brace group of several commands piped into a text filter.
//!
//! `for f in tests/*.py; do rg -l x "$f"; done | head -100` was reviewed
//! although the same loop without `| head -100` was allowed, and so was
//! `{ echo a; echo b; } | head`. The filters only reshape what they read, so
//! the group is read as its list, and the filters are proved after a constant
//! producer. A consumer that runs or opens what it reads keeps the review.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn a_list_piped_into_text_filters_is_decided_as_its_list() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/piped-group-filter-fixtures")
        .join(format!("fixture-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("work/tests")).unwrap();
    std::fs::create_dir_all(root.join(".aws")).unwrap();
    let root = std::fs::canonicalize(&root).unwrap();
    std::fs::write(root.join("work/tests/one.py"), "def test_one(): pass\n").unwrap();
    std::fs::write(root.join("work/tests/two.py"), "def test_two(): pass\n").unwrap();
    std::fs::write(root.join(".aws/credentials"), "[default]\n").unwrap();
    let home = root.to_str().unwrap();
    let cwd = root.join("work");
    let cwd = cwd.to_str().unwrap();
    for harness in ["codex", "omp"] {
        for (command, allowed) in [
            (
                "for f in tests/*.py; do rg -l download \"$f\"; done | head -100",
                true,
            ),
            ("for f in a b; do echo $f; done | head", true),
            (
                "{ rg -l download tests/one.py; rg -l download tests/two.py; } | head -100",
                true,
            ),
            ("{ echo a; echo b; } | sort | uniq -c", true),
            (
                "{ wc -l tests/one.py; wc -l tests/two.py; } | sort -n | tail -1",
                true,
            ),
            // The list still has to be allowed on its own.
            ("for f in ~/.aws/*; do cat \"$f\"; done | head", false),
            ("{ cat ~/.aws/credentials; echo a; } | head", false),
            ("{ echo a; rm tests/one.py; } | head", false),
            // So do the filters, and only filters qualify.
            (
                "for f in tests/*.py; do cat \"$f\"; done | head > out.txt",
                false,
            ),
            ("{ echo a; echo b; } | sort -o out.txt", false),
            ("{ ls tests; ls .; } | xargs cat", false),
            ("{ echo a; echo b; } | sh", false),
            // A loop behind `cd DIR &&` runs its filters in DIR, where the
            // group would prove them in the caller's directory.
            (
                "cd ../.aws && for f in a; do echo $f; done | cat credentials",
                false,
            ),
            (
                &format!("cd {home}/.aws && for f in a; do echo $f; done | cat credentials"),
                false,
            ),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                None,
                None,
                Some(home),
                Some(cwd),
            );
            assert_eq!(
                result.minimum_action == "allow",
                allowed,
                "{harness}: {command} => {} / {}",
                result.minimum_action,
                result.reason_code
            );
        }
    }
}
