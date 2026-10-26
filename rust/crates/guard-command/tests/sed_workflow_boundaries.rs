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
        "sed -n 1p '--expression=1e id'",
        "sed 's/a/b/' -fprog.sed",
        "sed -n 1p -i",
    ] {
        assert_ne!(action(command), "allow", "{command}");
    }
}

#[test]
fn line_range_reads_of_a_copy_are_allowed_in_every_spelling() {
    for command in [
        "sed -n '36,37' src/example.py",
        "sed -n '39' src/example.py",
        "sed -n 36 src/example.py",
        "sed -n '36, 37'p src/example.py",
        "sed -n -e 36p -e 39p src/example.py",
        "tail -n +31 src/example.py | head -20",
        "tail -n+31 src/example.py",
        "tail -c +10 src/example.py",
        "tail --lines=+31 src/example.py",
        "tail -n 20 src/example.py | head -5",
        "sed -n '36,39p' src/example.py | cat -n",
        "sed -n '36,39p' src/example.py | cat -A",
        r"sed -n '91'p src/example.py | sed 's/\(const\)/\1/'",
        r"grep -n const src/example.py | sed -E 's/(const)/\1/'",
        r"sed 's/\(const\)/\1/' src/example.py",
        "sed -n '36,39'p src/example.py | cat -A 2>/dev/null || sed -n '36,39'p src/example.py",
    ] {
        assert_eq!(action(command), "allow", "{command}");
    }
}

#[test]
fn line_range_read_spellings_do_not_admit_writes_or_other_files() {
    for command in [
        "tail -f src/example.py",
        "tail +31 src/example.py",
        "tail -n +31 .env",
        "tail +31 ~/.ssh/id_rsa",
        "tail -n +x src/example.py",
        "tail -n + src/example.py",
        "tail -n+ src/example.py",
        "sed -n '36,37' .env",
        "sed -n '36,37w out.txt' src/example.py",
        "sed -n '36,37;w out.txt' src/example.py",
        "sed -n -e 36p -e 'w out.txt' src/example.py",
        "sed -n -e 36p -e '1e id' src/example.py",
        "sed -n -e 36p -e src/example.py",
        "sed -n '/Example/,37p' src/example.py",
        "sed -n '36,37,38p' src/example.py",
        "sed -n '36 37p' src/example.py",
        "sed -n '36,37' -i src/example.py",
        "sed -n '36;' src/example.py",
        "sed '36,37' src/example.py",
        "sed -n '36,39p' src/example.py | cat .env",
        "sed -n '36,39p' src/example.py | cat -f",
        "sed -n '36,39p' src/example.py | sed 's/a/b/w out.txt'",
        "sed -n '36,39p' src/example.py | sed 's/a/b/e'",
        r"sed -n '36,39p' src/example.py | sed -i 's/\(a\)/\1/'",
        r"sed 's/\(a\)/\1/;w out.txt' src/example.py",
        r"sed -E 's/(a)/\1/w out.txt' src/example.py",
        r"sed -E 's/(a)/\1/' .env",
    ] {
        assert_ne!(action(command), "allow", "{command}");
    }
}
