use guard_command::{pretool::evaluate_pre_tool, CommandModelRequestV1};

fn decision(command: &str) -> String {
    evaluate_pre_tool(&CommandModelRequestV1 {
        command: command.into(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "workflow-fixture".into(),
    })
    .unwrap()
    .minimum_action
}

#[test]
fn numeric_expression_proof_excludes_execution_and_resource_amplification() {
    for command in [
        "python3 -c 'print(1 + 1)'",
        "python -c 'print((12 - 3) * 2)'",
        "node -e 'console.log(7 % 2)'",
        "nodejs -e 'console.log(-2 + 5)'",
    ] {
        assert_eq!(decision(command), "allow", "{command}");
    }
    for command in [
        "python3 -c 'print(__import__(\"os\").system(\"rm -rf project\"))'",
        "python3 -c 'print(1); import shutil; shutil.rmtree(\"project\")'",
        "python3 -c 'print(open(\".env\").read())'",
        "python3 -c 'print(9 ** 999999999)'",
        "python3 -c 'print(999999999999999999999999)'",
        "node -e 'console.log(require(\"fs\").readFileSync(\".env\"))'",
        "node -e 'console.log(1); process.exit()'",
        "node --require ./startup.js -e 'console.log(1 + 1)'",
        "python3 -c 'print((lambda: 1)())'",
        "python3 -c 'print(1)' project.py",
    ] {
        assert_ne!(decision(command), "allow", "{command}");
    }
}
