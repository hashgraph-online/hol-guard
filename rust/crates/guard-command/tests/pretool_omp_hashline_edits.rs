#![cfg(any(unix, windows))]

use serde_json::json;

use crate::git_helper_fixture as fixture;
use fixture::evaluate_pre_tool_envelope_with_context;

fn patch(sections: &[&str]) -> String {
    format!("*** Begin Patch\n{}*** End Patch\n", sections.concat())
}

#[test]
fn oh_my_pi_hashline_edits_get_the_file_write_proof() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/omp-hashline-fixtures")
        .join(format!(
            "case-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let _cleanup = fixture::FixtureCleanup(root.clone());
    let home = fixture::canonical_spelling(&root);
    let workspace = home.join("project");
    let sibling = home.join("project-fix");
    for directory in [&workspace, &sibling] {
        std::fs::create_dir_all(directory.join("src")).unwrap();
        std::fs::create_dir_all(directory.join(".git")).unwrap();
        std::fs::write(directory.join("src/a.ts"), "export const a = 1;\n").unwrap();
    }
    std::fs::write(workspace.join("src/b.ts"), "export const b = 2;\n").unwrap();
    std::fs::write(
        workspace.join("package.json"),
        "{\n  \"scripts\": {\n    \"test\": \"echo none\"\n  }\n}\n",
    )
    .unwrap();
    std::fs::write(workspace.join(".env"), "TOKEN=synthetic\n").unwrap();
    std::fs::write(workspace.join("AGENTS.md"), "rules\n").unwrap();
    std::fs::write(workspace.join(".git/config"), "[core]\n").unwrap();
    std::fs::write(home.join(".zshrc"), "export PATH\n").unwrap();
    let in_sibling = format!(
        "[{}#0AC4]\nPUT 1.=1:\n+export const a = 3;\n",
        sibling.join("src/a.ts").display()
    );
    let absolute = format!(
        "[{}#0AC4]\nPUT >$:\n+// end\n",
        workspace.join("src/a.ts").display()
    );
    let put_a = "[src/a.ts#0AC4]\nPUT 1.=1:\n+export const a = 3;\n";
    let put_b = "[src/b.ts#1B2C]\nPUT <1:\n+import { a } from './a';\n";
    let missing = "[project-fix-typo/src/a.ts#0AC4]\nPUT 1.=1:\n+x\n";

    let evaluate = |harness: &str, input: &str| {
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": "edit", "tool_input": {"input": input}}),
            None,
            None,
            home.to_str(),
            workspace.to_str(),
        )
    };
    for input in [
        patch(&[put_a]),
        patch(&[put_a, put_b]),
        patch(&[&absolute]),
        patch(&[&in_sibling, put_b]),
        patch(&["[src/new.ts]\nPUT >$:\n+export {};\n"]),
        // Oh My Pi opens a leading `~/` under the home folder.
        patch(&["[~/project/src/a.ts#0AC4]\nPUT >$:\n+// end\n", put_b]),
        patch(&["[ ~/project-fix/src/a.ts#0AC4]\nPUT 1.=1:\n+export const a = 3;\n"]),
        patch(&[
            "[src/a.ts#0AC4]\nCUT 1.=1 @line\n",
            "[src/b.ts#1B2C]\nPUT >$ @line\n",
        ]),
        // Unified-diff `-old` rows under a `PUT` are body, not operations.
        patch(&["[src/a.ts#0AC4]\nPUT 1.=1:\n-export const a = 1;\n+export const a = 3;\n"]),
        patch(&["[package.json#0AC4]\nPUT 3.=3:\n-    \"test\": \"echo none\"\n+    \"test\": \"node --test\"\n"]),
    ] {
        let result = evaluate("omp", &input);
        assert_eq!(
            (result.minimum_action.as_str(), result.reason_code.as_str()),
            ("allow", "native_exact_safe_file_write"),
            "{input}"
        );
    }
    // A file that does not exist cannot be edited; the agent fixes the path.
    for input in [
        patch(&[missing]),
        patch(&[put_a, missing]),
        patch(&["[~/project-typo/src/a.ts#0AC4]\nPUT 1.=1:\n+x\n"]),
    ] {
        let result = evaluate("omp", &input);
        assert_eq!(
            (result.minimum_action.as_str(), result.reason_code.as_str()),
            ("block", "native_missing_path"),
            "{input}"
        );
    }
    // The reason names the missing path, and says where a relative one is
    // read from.
    let result = evaluate("omp", &patch(&[put_a, missing]));
    assert!(
        result
            .reason
            .contains("`project-fix-typo/src/a.ts` does not exist. A relative path is read from the session folder"),
        "{}",
        result.reason
    );
    let result = evaluate(
        "omp",
        &patch(&["[~/project-typo/src/a.ts#0AC4]\nPUT 1.=1:\n+x\n"]),
    );
    assert!(
        result
            .reason
            .contains("`~/project-typo/src/a.ts` does not exist. Check the path"),
        "{}",
        result.reason
    );
    for input in [
        patch(&["[.env#0AC4]\nPUT 1.=1:\n+TOKEN=changed\n"]),
        patch(&[put_a, "[.env#0AC4]\nPUT >$:\n+EXTRA=1\n"]),
        patch(&["[missing/.env#0AC4]\nPUT >$:\n+TOKEN=x\n"]),
        patch(&["[AGENTS.md#0AC4]\nPUT >$:\n+more rules\n"]),
        patch(&["[.git/config#0AC4]\nPUT >$:\n+[alias]\n"]),
        patch(&["[.git/hooks/pre-commit]\nPUT >$:\n+exit 0\n"]),
        patch(&["[src/a.ts#0AC4]\nREM\n"]),
        patch(&["[src/a.ts#0AC4]\nMV ../outside.ts\n"]),
        patch(&["[~/.zshrc#0AC4]\nPUT >$:\n+export X=1\n"]),
        patch(&["[~/.ssh/config]\nPUT >$:\n+Host *\n"]),
        patch(&["[~/project/.env#0AC4]\nPUT >$:\n+EXTRA=1\n"]),
        patch(&["[~/project/AGENTS.md#0AC4]\nPUT >$:\n+more rules\n"]),
        patch(&["[*** Update File: src/a.ts#0AC4]\nPUT 1.=1:\n+x\n"]),
        "*** Begin Patch\n*** Update File: src/a.ts\n@@\n-export const a = 1;\n+export const a = 3;\n*** End Patch\n".to_owned(),
    ] {
        let result = evaluate("omp", &input);
        assert_eq!(result.minimum_action, "review", "{input}: {result:?}");
    }
    // Only Oh My Pi's edit tool takes a hashline patch.
    let result = evaluate("claude-code", &patch(&[put_a]));
    assert_ne!(result.minimum_action, "allow", "{result:?}");
}

#[test]
fn oh_my_pi_header_copies_keep_the_file_write_proof() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/omp-hashline-fixtures")
        .join(format!(
            "derived-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let _cleanup = fixture::FixtureCleanup(root.clone());
    let workspace = fixture::canonical_spelling(&root).join("project");
    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::create_dir_all(workspace.join(".git")).unwrap();
    std::fs::write(workspace.join("src/a.ts"), "export const a = 1;\n").unwrap();
    std::fs::write(workspace.join("src/b.ts"), "export const b = 2;\n").unwrap();
    std::fs::write(workspace.join(".env"), "TOKEN=synthetic\n").unwrap();
    let put_a = "[src/a.ts#0AC4]\nPUT 1.=1:\n+export const a = 3;\n";
    let put_b = "[src/b.ts#1B2C]\nPUT <1:\n+import { a } from './a';\n";
    let missing = "[project-typo/src/a.ts#0AC4]\nPUT 1.=1:\n+x\n";

    let evaluate = |tool_input: serde_json::Value| {
        let result = evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name": "edit", "tool_input": tool_input}),
            None,
            None,
            root.to_str(),
            workspace.to_str(),
        );
        (result.minimum_action, result.reason_code)
    };
    let allowed = (
        "allow".to_owned(),
        "native_exact_safe_file_write".to_owned(),
    );
    // Oh My Pi 18.8 copies one header into `path` and `paths`, and several
    // headers, repeats included, into `paths` alone.
    assert_eq!(
        evaluate(json!({"input": patch(&[put_a]), "path": "src/a.ts", "paths": ["src/a.ts"]})),
        allowed
    );
    assert_eq!(
        evaluate(json!({"input": patch(&[put_a, put_b]), "paths": ["src/a.ts", "src/b.ts"]})),
        allowed
    );
    assert_eq!(
        evaluate(json!({
            "input": patch(&[put_a, put_b, put_a]),
            "paths": ["src/a.ts", "src/b.ts", "src/a.ts"],
        })),
        allowed
    );
    // A wrong path still says it is missing, so the agent fixes it.
    assert_eq!(
        evaluate(json!({
            "input": patch(&[missing]),
            "path": "project-typo/src/a.ts",
            "paths": ["project-typo/src/a.ts"],
        })),
        ("block".to_owned(), "native_missing_path".to_owned())
    );
    // Fields that are not an exact copy of the headers keep the review.
    for tool_input in [
        json!({"input": patch(&[put_a]), "path": ".env", "paths": ["src/a.ts"]}),
        json!({"input": patch(&[put_a]), "path": "src/a.ts", "paths": [".env"]}),
        json!({"input": patch(&["[.env#0AC4]\nPUT >$:\n+EXTRA=1\n"]), "paths": ["src/a.ts"]}),
        json!({"input": patch(&["[.env#0AC4]\nPUT >$:\n+EXTRA=1\n"]), "path": "src/a.ts"}),
        json!({"input": patch(&[put_a, put_b]), "paths": ["src/b.ts", "src/a.ts"]}),
        json!({"input": patch(&[put_a, put_b]), "paths": ["src/a.ts", "src/b.ts", ".env"]}),
        json!({"input": patch(&[put_a, put_b]), "path": "src/a.ts", "paths": ["src/a.ts", "src/b.ts"]}),
        json!({"input": patch(&[put_a]), "path": "src/a.ts", "paths": ["src/a.ts"], "mode": "x"}),
        json!({"input": patch(&["[.env#0AC4]\nPUT >$:\n+EXTRA=1\n"]), "path": ".env", "paths": [".env"]}),
    ] {
        assert_ne!(evaluate(tool_input.clone()), allowed, "{tool_input}");
    }
}

#[test]
fn todo_updates_sent_to_edit_name_no_file() {
    let home = std::env::temp_dir();
    let evaluate = |input: serde_json::Value| {
        evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name": "edit", "tool_input": input}),
            None,
            None,
            home.to_str(),
            home.to_str(),
        )
    };
    let todo = evaluate(json!({
        "input": "done", "phase": "Implement game", "task": "Build canvas gameplay"
    }));
    assert_eq!(todo.minimum_action, "allow");
    assert_eq!(todo.reason_code, "native_omp_edit_without_target");
    for input in [
        json!({"input": "[game.js#250F]\nPUT 1.=1:\n+x\n", "phase": "Implement game"}),
        json!({"input": "*** Begin Patch\n*** Update File: game.js\n+x\n*** End Patch", "task": "t"}),
        json!({"input": "done", "phase": "p", "path": "game.js"}),
        json!({"input": "done\n+x", "phase": "p"}),
        json!({"input": "done", "phase": "p", "edits": []}),
        json!({"input": "done"}),
        json!({"input": "game.js", "task": "t"}),
    ] {
        assert_ne!(
            evaluate(input.clone()).reason_code,
            "native_omp_edit_without_target",
            "{input}"
        );
    }
}

#[test]
fn edits_without_a_file_header_name_no_file() {
    let home = std::env::temp_dir();
    let evaluate = |input: serde_json::Value| {
        evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name": "edit", "tool_input": input}),
            None,
            None,
            home.to_str(),
            home.to_str(),
        )
    };
    // Calls a model meant for read and bash; Oh My Pi refused both.
    for input in [
        json!({"input": "test/game.test.js"}),
        json!({"input": "node --test", "timeout": 120}),
        json!({"input": "done"}),
        json!({"input": "~/.ssh/id_ed25519"}),
    ] {
        let result = evaluate(input.clone());
        assert_eq!(result.minimum_action, "allow", "{input}");
        assert_eq!(
            result.reason_code, "native_omp_edit_without_header",
            "{input}"
        );
    }
    for input in [
        json!({"input": "[.env#0AC4]\nPUT >$:\n+EXTRA=1\n"}),
        json!({"input": "[.env]"}),
        json!({"input": "*** Begin Patch\n*** Add File: .env\n+X=1\n*** End Patch"}),
        json!({"input": "*** Edit File: .env"}),
        json!({"input": "\u{b6}.env"}),
        json!({"input": "game.js\n+x"}),
        json!({"input": "game.js", "path": "game.js"}),
        json!({"input": "game.js", "timeout": "120"}),
        json!({"input": "game.js", "edits": []}),
        json!({"input": 7}),
    ] {
        assert_ne!(
            evaluate(input.clone()).reason_code,
            "native_omp_edit_without_header",
            "{input}"
        );
    }
}
