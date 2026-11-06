#![cfg(unix)]
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::{json, Value};

struct Fixture {
    root: std::path::PathBuf,
    home: std::path::PathBuf,
    project: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn fixture() -> Fixture {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-literal-route-writes")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let project = home.join("project");
    for file in [
        "project/app/registry/[slug]/page.tsx",
        "project/app/[id]/settings.ts",
        "project/app/routes/posts.$slug.tsx",
        "project/CLAUDE.md",
        "project/.git/hooks/pre-commit",
        ".ssh/config",
    ] {
        let path = home.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "synthetic fixture\n").unwrap();
    }
    std::fs::create_dir_all(root.join("outside")).unwrap();
    std::os::unix::fs::symlink(home.join(".ssh"), project.join("app/[link]")).unwrap();
    std::os::unix::fs::symlink(root.join("outside"), project.join("app/routes/$link")).unwrap();
    Fixture {
        root,
        home,
        project,
    }
}

fn run(f: &Fixture, harness: &str, tool: &str, input: Value) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": input}),
        None,
        None,
        f.home.to_str(),
        f.project.to_str(),
    )
}

fn host_write(f: &Fixture, harness: &str, path: &str) -> guard_contracts::PreToolResultV1 {
    match harness {
        "omp" => run(f, harness, "write", json!({"path": path, "content": "x\n"})),
        _ => run(
            f,
            harness,
            "Write",
            json!({"file_path": path, "content": "x\n"}),
        ),
    }
}

#[test]
fn dynamic_route_files_are_literal_workspace_writes() {
    let f = fixture();
    let existing = f.project.join("app/registry/[slug]/page.tsx");
    let new_subtree = f
        .project
        .join("app/api/guard/extensions/[id]/promotion/local-distribution/route.ts");
    let catch_all = f.project.join("app/docs/[...slug]/page.tsx");
    let optional = f.project.join("app/shop/[[...slug]]/page.tsx");
    for harness in ["claude-code", "zcode", "omp"] {
        for path in [&existing, &new_subtree, &catch_all, &optional] {
            let path = path.to_str().unwrap();
            let result = host_write(&f, harness, path);
            assert_eq!(
                (result.minimum_action.as_str(), result.reason_code.as_str()),
                ("allow", "native_exact_safe_file_write"),
                "{harness} {path}"
            );
        }
        let result = host_write(&f, harness, "app/[id]/settings.ts");
        assert_eq!(result.minimum_action, "allow", "{harness}: {result:?}");
    }
    let existing = existing.to_str().unwrap();
    let result = run(
        &f,
        "claude-code",
        "Edit",
        json!({"file_path": existing, "old_string": "synthetic", "new_string": "updated"}),
    );
    assert_eq!(result.minimum_action, "allow", "{result:?}");
    let result = run(
        &f,
        "omp",
        "edit",
        json!({"path": "app/[id]/settings.ts", "oldText": "synthetic", "newText": "updated"}),
    );
    assert_eq!(result.minimum_action, "allow", "{result:?}");
}

fn multi_edit(f: &Fixture, harness: &str, path: &str) -> guard_contracts::PreToolResultV1 {
    run(
        f,
        harness,
        "MultiEdit",
        json!({"file_path": path, "edits": [{"old_string": "synthetic", "new_string": "updated"}]}),
    )
}

#[test]
fn dollar_route_files_are_literal_workspace_writes() {
    let f = fixture();
    for harness in ["claude-code", "zcode", "omp"] {
        for path in [
            "app/routes/$postId.tsx",
            "app/routes/posts.$slug.tsx",
            "app/routes/posts.$slug.edit.tsx",
            "app/routes/$.tsx",
            "src/routes/users/$userId/index.tsx",
        ] {
            let absolute = f.project.join(path);
            for spelling in [path, absolute.to_str().unwrap()] {
                let result = host_write(&f, harness, spelling);
                assert_eq!(
                    (result.minimum_action.as_str(), result.reason_code.as_str()),
                    ("allow", "native_exact_safe_file_write"),
                    "{harness} {spelling}"
                );
            }
        }
    }
}

#[test]
fn multi_edit_is_a_write_with_the_write_screens() {
    let f = fixture();
    for harness in ["claude-code", "zcode"] {
        for path in [
            "app/registry/[slug]/page.tsx",
            "app/routes/posts.$slug.tsx",
            "app/[id]/settings.ts",
        ] {
            let path = f.project.join(path);
            let result = multi_edit(&f, harness, path.to_str().unwrap());
            assert_eq!(
                (result.minimum_action.as_str(), result.reason_code.as_str()),
                ("allow", "native_exact_safe_file_write"),
                "{harness} {path:?}"
            );
        }
        // A MultiEdit follows the Write and Edit rules: plain instruction
        // files stay writable, while a Git hook keeps the write review even
        // though the existing file is readable.
        let instructions = f.project.join("CLAUDE.md");
        let result = multi_edit(&f, harness, instructions.to_str().unwrap());
        assert_eq!(result.minimum_action, "allow", "{harness} {instructions:?}");
        let hook = f.project.join(".git/hooks/pre-commit");
        let result = multi_edit(&f, harness, hook.to_str().unwrap());
        assert_ne!(result.minimum_action, "allow", "{harness} {hook:?}");
    }
}

#[test]
fn literal_route_writes_keep_every_other_screen() {
    let f = fixture();
    let outside = f.root.join("outside/[id]/route.ts");
    let home_dotfile = f.home.join(".zshrc");
    let git_hook = f.project.join(".git/hooks/pre-commit");
    for path in [
        // Other glob metacharacters stay rejected, and parent components
        // never reach past the workspace and verified home.
        "app/[id]/*.ts",
        "app/{a,b}/[id].ts",
        "app/[id]/../../../../outside/escape.ts",
        // A bracketed directory that links elsewhere resolves to its target.
        "app/[link]/config",
        // Hidden and protected targets inside the workspace stay reviewed.
        "app/[id]/.env",
        "[id]/.git/hooks/post-checkout",
        git_hook.to_str().unwrap(),
        ".claude/settings.json",
        // Writes outside the workspace and verified home stay reviewed.
        outside.to_str().unwrap(),
        home_dotfile.to_str().unwrap(),
        // `$` is a literal name only; it never widens a target either.
        "app/routes/$link/escape.ts",
        "app/routes/.env.$stage",
        "app/routes/$id/.env",
        ".git/hooks/$hook",
        ".husky/$hook",
        "app/routes/$id.tsx::$DATA",
        "app/routes/$id/*.tsx",
        "app/routes/$id/../../../../outside/escape.ts",
    ] {
        for harness in ["claude-code", "zcode", "omp"] {
            let result = host_write(&f, harness, path);
            assert_ne!(
                result.minimum_action, "allow",
                "{harness} {path}: {result:?}"
            );
        }
    }
}
