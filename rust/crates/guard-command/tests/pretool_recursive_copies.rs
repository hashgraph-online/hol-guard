#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::Path;
use std::process::Command;

fn permitted(command: &str, home: &Path, workspace: &Path) -> bool {
    let evaluate = |harness| {
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"toolName": "Bash", "toolInput": {"command": command}}),
            None,
            None,
            home.to_str(),
            workspace.to_str(),
        )
        .minimum_action
    };
    let zcode = evaluate("zcode");
    assert_eq!(zcode, evaluate("omp"), "host policy drift: {command}");
    zcode == "allow"
}

fn write(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "synthetic fixture").unwrap();
}

#[test]
fn recursive_copies_create_new_trees_only() {
    // Avoid macOS's protected /private/var temporary root.
    let home = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-recursive-copies")
        .join(format!("home-{}", std::process::id()));
    let project = home.join("project");
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&project).unwrap();
    assert!(Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(&project)
        .status()
        .unwrap()
        .success());
    for path in [
        "src/index.ts",
        "src/nested/util.ts",
        "src/[slug]/page.tsx",
        "src/password-reset-email.tsx",
        "secrets/.env",
        "keys/id_rsa",
        "linked/readme.md",
        "existing/readme.md",
        "occupied/src/readme.md",
    ] {
        write(&project.join(path));
    }
    write(&home.join("outside/readme.md"));
    write(&home.join(".ssh/config"));
    std::os::unix::fs::symlink(home.join(".ssh/config"), project.join("linked/config")).unwrap();
    std::os::unix::fs::symlink(project.join("src"), project.join("src-alias")).unwrap();
    let home = std::fs::canonicalize(&home).unwrap();
    let project = std::fs::canonicalize(&project).unwrap();
    for command in [
        "cp -R src src-copy",
        "cp -r src existing",
        "cp --recursive -- src build-src",
        "cp -R src/ fresh-copy",
        "cp -R src/nested nested-copy",
        "cp -R src existing/",
        // A new visible tree in the home and a plain dot-named scratch tree
        // pass the same screens as `mkdir`.
        "cp -R src ~/outside/copy",
        "cp -R src .scratch-copy",
    ] {
        assert!(permitted(command, &home, &project), "{command}");
    }
    for command in [
        "cp -R src occupied",
        "cp -R src/ existing",
        "cp -R src/. existing",
        "cp -R src/nested/.. existing",
        "cp -R . existing",
        "cp -R src src/inner",
        "cp -R src src/nested/inner",
        "cp -R src existing/readme.md",
        "cp -R secrets copied",
        "cp -R keys copied",
        "cp -R linked copied",
        "cp -R src-alias copied",
        "cp -R src-alias/nested alias-copy",
        "cp -R src .git/hooks-copy",
        "cp -R src .husky",
        "cp -R src .vscode",
        "cp -R src .claude/skills",
        "cp -R src ~/.copy",
        "cp -R src ~/bin",
        "cp -R src ~/.ssh/copy",
        "cp -R ~/.ssh ssh-copy",
        "cp -R src/index.ts copied.ts",
        "cp -Rf src forced",
        "cp -R -L src followed",
        "cp -R src one two",
        "cp -R src copy && echo done",
    ] {
        assert!(!permitted(command, &home, &project), "{command}");
    }
    std::fs::remove_dir_all(home).unwrap();
}
