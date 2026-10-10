#![cfg(unix)]
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn sdk_read_helper_uses_file_policy_and_rejects_unmodeled_programs() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-omp-eval-read-helpers")
        .join(format!("home-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(&project).unwrap();
    for path in [
        ".agent/skills/x/SKILL.md",
        ".ssh/id_rsa",
        "project/README.md",
    ] {
        let file = home.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, "synthetic fixture\n").unwrap();
    }
    std::os::unix::fs::symlink(home.join(".ssh/id_rsa"), project.join("linked.md")).unwrap();
    let evaluate = |code: &str| {
        evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"eval","tool_input":{"language":"js","code":code}}),
            None,
            None,
            home.to_str(),
            project.to_str(),
        )
    };
    let baseline = evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"read","tool_input":{"path":"~/.agent/skills/x/SKILL.md"}}),
        None,
        None,
        home.to_str(),
        project.to_str(),
    );
    assert_eq!(baseline.minimum_action, "allow", "{}", baseline.reason_code);
    let skill_path =
        serde_json::to_string(home.join(".agent/skills/x/SKILL.md").to_str().unwrap()).unwrap();
    let skill_read = format!("display(await read({skill_path}))");
    let secret_path = serde_json::to_string(home.join(".ssh/id_rsa").to_str().unwrap()).unwrap();
    let secret_read = format!("display(await read({secret_path}))");
    for code in [
        skill_read.as_str(),
        "const r = await read('README.md'); display(r)",
        "display(await read(`README.md`))",
    ] {
        let result = evaluate(code);
        assert_eq!(
            result.minimum_action, "allow",
            "{code}: {}",
            result.reason_code
        );
    }
    for code in [
        secret_read.as_str(),
        "display(await read('linked.md'))",
        "display(await read('~/.ssh/id_rsa'))",
        "display(await read('~/.agent/skills/x/SKILL.md'))",
        "display(await read('README.md:1-120'))",
        "display(await read(' README.md '))",
        "display(await read('README.md\\n'))",
        "display(await read('dir\\\\README.md'))",
        "display(await read('.env'))",
        "display(await read('https://example.com'))",
        "display(await read('proc://job'))",
        "const p = 'README.md'; display(await read(p))",
        "display(await read('README' + '.md'))",
        "display(await read(`${home}/README.md`))",
        "const read = 'other'; display(await read('README.md'))",
        "let read = await tool.read({path:'README.md'}); display(await read('README.md'))",
        "display(await read('README.md', 'other'))",
        "display(await read('README.md')); await fetch('https://example.com')",
    ] {
        assert_ne!(evaluate(code).minimum_action, "allow", "{code}");
    }
    std::fs::remove_dir_all(root).unwrap();
}
