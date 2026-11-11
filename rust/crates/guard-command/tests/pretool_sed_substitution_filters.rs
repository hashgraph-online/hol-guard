#![cfg(unix)]

//! A redaction filter in the middle of a read-only pipeline.
//!
//! `sed -E 's/\/tmp\/scratch-[a-z0-9]+/TMPDIR/'` reads its input and writes
//! the rewritten text on, which is what every other filter in these pipelines
//! does. The substitution proof read the program by splitting it on every
//! slash, so a redaction that names a path -- and therefore escapes the
//! slashes inside its own pattern -- counted as more parts than a
//! substitution has and sent the whole pipeline to review. The same split
//! refused `p`, `i` and an occurrence count, which change nothing outside the
//! stream either, and it refused a script that spells its own delimiter or
//! chains substitutions with a semicolon. The commands that do reach past the
//! stream still stop here: `w` names a file to write, `r` reads one into the
//! output, `e` hands the pattern space to a shell, and `-i` rewrites the file
//! in place.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn a_substitution_filter_stays_inside_the_stream() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/sed-substitution-fixtures")
        .join(format!("fixture-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("one.txt"), "ordinary fixture\n").unwrap();
    std::fs::write(root.join(".env"), "SYNTHETIC_ONLY=fixture\n").unwrap();
    for harness in ["omp", "zcode"] {
        for (command, allowed) in [
            (
                r"cat one.txt | sed -E 's/\/tmp\/scratch-[a-z0-9]+/TMPDIR/'",
                true,
            ),
            (
                r"cat one.txt | sed -E 's/\/tmp\/scratch-[a-z0-9]+/TMPDIR/g' | sort -u",
                true,
            ),
            ("cat one.txt | sed -E 's/alpha/beta/gI'", true),
            ("cat one.txt | sed -E 's/alpha/beta/2g'", true),
            ("cat one.txt | sed -n -E 's/alpha/beta/p'", true),
            (
                "cat one.txt | sed -e 's/alpha/beta/' -e 's/gamma/delta/'",
                true,
            ),
            ("cat one.txt | sed -E 's|alpha|beta|g'", true),
            ("cat one.txt | sed -E 's#alpha#beta#g'", true),
            ("cat one.txt | sed -E 's/alpha/beta/; s/gamma/delta/'", true),
            ("cat one.txt | sed 's/alpha/beta/' | head -40", true),
            ("cat one.txt | sed -E 's/alpha/beta/w captured.txt'", false),
            ("cat one.txt | sed -E 's/alpha/beta/e'", false),
            ("cat one.txt | sed -E 's|alpha|beta|w captured.txt'", false),
            (
                "cat one.txt | sed -E 's/alpha/beta/; w captured.txt'",
                false,
            ),
            (
                "cat one.txt | sed -E 's/alpha/beta/; s/gamma/delta/e'",
                false,
            ),
            (
                "cat one.txt | sed -e 's/alpha/beta/' -e 'w captured.txt'",
                false,
            ),
            ("cat one.txt | sed -e 's/alpha/beta/' -e 'r .env'", false),
            ("cat one.txt | sed -E 's/alpha/beta/' .env", false),
            ("cat one.txt | sed -i -E 's/alpha/beta/' one.txt", false),
            ("cat one.txt | sed -E 's/alpha/beta'", false),
            ("cat .env | sed -E 's/alpha/beta/'", false),
            ("sed -E 's/alpha/beta/'", false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                None,
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(
                result.minimum_action == "allow",
                allowed,
                "{harness}: {command}"
            );
        }
    }
}
