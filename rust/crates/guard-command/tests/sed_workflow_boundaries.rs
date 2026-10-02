use guard_command::pretool::evaluate_pre_tool;
use guard_command::CommandModelRequestV1;

fn action(command: &str) -> String {
    evaluate_pre_tool(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "workflow-fixture".to_owned(),
    })
    .unwrap()
    .minimum_action
}

#[test]
fn routine_sed_reads_and_inert_pipeline_formatting_are_allowed() {
    for command in [
        "sed -n '1,20p' src/example.py",
        "sed -n '20p' src/example.py",
        "grep -n Example src/example.py | sed 's/^/MATCH /'",
        "cat src/example.py | sed 's/Example/Sample/g'",
    ] {
        assert_eq!(action(command), "allow", "{command}");
    }
}

#[test]
fn sed_risky_programs_never_inherit_read_allowance() {
    for command in [
        "sed -i 's/Example/Sample/' src/example.py",
        "sed -f program.sed src/example.py",
        "sed 's/Example/Sample/e' src/example.py",
        "sed 's/Example/Sample/w output.txt' src/example.py",
        "sed 's/Example/Sample/;e id' src/example.py",
        "sed -n '1,20p' .env",
        "sed -n '1,20p' ~/.ssh/id_rsa",
        "sed -n '1,20p' /etc/passwd",
        "cat .env | sed 's/^/MATCH /'",
        "sed 's/^/MATCH /'",
        "sed -n '0p' src/example.py",
    ] {
        assert_ne!(action(command), "allow", "{command}");
    }
}
