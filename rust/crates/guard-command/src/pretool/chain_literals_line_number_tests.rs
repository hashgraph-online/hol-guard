use super::super::project;
use super::stand_in;

fn projected(command: &str) -> Option<String> {
    project(command, |_| true)
}

#[test]
fn a_line_number_lookup_opens_a_sed_range() {
    for (command, expected) in [
        (
            "sed -n \"$(grep -n 'fn main' src/main.rs | cut -d: -f1),+20p\" src/main.rs",
            "sed -n \"1,+20p\" src/main.rs",
        ),
        (
            "sed -n \"$(grep -n 'export function load' ../app/src/load.ts | head -1 | cut -d: -f1),+40p\" ../app/src/load.ts",
            "sed -n \"1,+40p\" ../app/src/load.ts",
        ),
        (
            "grep -n load src/a.ts | head -3; sed -n \"$(grep -nE '^export (async )?function load' src/a.ts | cut -d : -f 1 | head -n 1),60p\" src/a.ts",
            "grep -n load src/a.ts | head -3; sed -n \"1,60p\" src/a.ts",
        ),
        (
            "sed -n -e \"$(grep -n -m 1 'const rows' t.test.ts | cut -f1 -d:),+12p\" t.test.ts",
            "sed -n -e \"1,+12p\" t.test.ts",
        ),
        (
            "sed -n $(grep -n Slug content.ts | cut -d: -f1),+12p content.ts",
            "sed -n 1,+12p content.ts",
        ),
    ] {
        assert_eq!(projected(command).as_deref(), Some(expected), "{command}");
    }
}

#[test]
fn a_line_number_lookup_anywhere_else_stays_opaque() {
    for command in [
        // Not the opening of a range.
        "sed -n \"$(grep -n x a.ts | cut -d: -f1)p\" a.ts",
        "sed -n \"10,$(grep -n x a.ts | cut -d: -f1)p\" a.ts",
        // Glued to text before it, or after an operand.
        "sed -n \"5$(grep -n x a.ts | cut -d: -f1),+3p\" a.ts",
        "sed -n -f script.sed \"$(grep -n x a.ts | cut -d: -f1),+3p\"",
        // Not a sed script: a file name or another program's argument.
        "cat \"$(grep -n x a.ts | cut -d: -f1),x\"",
        "head -n \"$(grep -n x a.ts | cut -d: -f1),\" a.ts",
        "rm \"$(grep -n x a.ts | cut -d: -f1)\"",
        "echo ok; sed -n '$(grep -n x a.ts | cut -d: -f1),+3p' a.ts",
    ] {
        assert_eq!(projected(command), None, "{command}");
    }
}

#[test]
fn only_a_lookup_that_prints_line_numbers_takes_the_stand_in() {
    for body in [
        "grep -n 'fn main' src/main.rs | cut -d: -f1",
        "grep --line-number -F 'a|b' src/main.rs | cut -d: -f1",
        "grep -inw main src/main.rs | head -2 | cut -d: -f1",
        "grep -n -m1 main src/main.rs | cut -d':' -f1",
    ] {
        assert_eq!(stand_in(body), Some("1"), "{body}");
    }
    for body in [
        // No -n, so the output is matched text.
        "grep main src/main.rs | cut -d: -f1",
        // Several files, a recursive search or a pattern put names in the output.
        "grep -n main src/a.rs src/b.rs | cut -d: -f1",
        "grep -rn main src | cut -d: -f1",
        "grep -n main src/*.rs | cut -d: -f1",
        "grep -n main ~/notes.md | cut -d: -f1",
        "grep -Hn main src/main.rs | cut -d: -f1",
        "grep -n main src/main.rs -r | cut -d: -f1",
        "grep -n main - | cut -d: -f1",
        // Another field, another delimiter, or no cut at all.
        "grep -n main src/main.rs | cut -d: -f2",
        "grep -n main src/main.rs | cut -d, -f1",
        "grep -n main src/main.rs | cut -c1-3",
        "grep -n main src/main.rs",
        "grep -n main src/main.rs | head -1",
        "grep -n main src/main.rs | cut -d: -f1 | sed s/1/x/",
        // Expansions and other shell text.
        "grep -n \"$HOME\" src/main.rs | cut -d: -f1",
        "grep -n main $FILE | cut -d: -f1",
        "grep -n main src/main.rs || cut -d: -f1",
        "grep -n main src/main.rs > out | cut -d: -f1",
        "grep -n main src/main.rs | cut -d: -f1; rm x",
        "grep -n main src/main.rs | head -1234567 | cut -d: -f1",
    ] {
        assert_eq!(stand_in(body), None, "{body}");
    }
}

#[test]
fn a_heredoc_that_holds_the_line_value_still_projects_anywhere() {
    assert_eq!(
        projected("echo \"$(cat <<'EOF'\n1\nEOF\n)\""),
        Some("echo \"1\"".to_owned())
    );
}
