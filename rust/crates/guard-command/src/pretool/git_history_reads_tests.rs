use super::read_form;

fn args(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn history_inspections_are_read_forms() {
    for (subcommand, rest) in [
        ("blame", ""),
        ("blame", "src/index.ts"),
        ("blame", "-L 1,20 src/index.ts"),
        ("blame", "-L1,20 src/index.ts"),
        ("blame", "--line-porcelain src/index.ts"),
        ("blame", "-w -M -C3 --date=short src/index.ts"),
        ("blame", "--abbrev=12 --show-email HEAD -- src/index.ts"),
        (
            "blame",
            "--ignore-revs-file .git-blame-ignore-revs src/index.ts",
        ),
        ("describe", ""),
        ("describe", "--tags"),
        ("describe", "--tags --always"),
        ("describe", "--match v* --exclude nightly/* HEAD"),
        ("describe", "--dirty=-wip --abbrev=7"),
        ("describe", "--contains --candidates 20 HEAD~3"),
        ("reflog", ""),
        ("reflog", "show main"),
        ("reflog", "-n 10"),
        ("reflog", "-5 --date=iso"),
        ("reflog", "--all --format=%h %gd"),
    ] {
        assert!(read_form(subcommand, &args(rest)), "{subcommand} {rest}");
    }
}

#[test]
fn other_forms_keep_review() {
    for (subcommand, rest) in [
        ("blame", "--textconv src/index.ts"),
        ("blame", "--output=blame.txt src/index.ts"),
        ("blame", "--exec-path=/tmp/evil src/index.ts"),
        ("blame", "-Cx src/index.ts"),
        ("blame", "-S.env src/index.ts"),
        ("blame", "-S../.ssh/id_rsa src/index.ts"),
        ("blame", "-L:secret:.env src/index.ts"),
        ("blame", "--abbrev=x src/index.ts"),
        ("describe", "--textconv"),
        ("describe", "--abbrev=x"),
        ("describe", "--unknown-option"),
        ("reflog", "expire --all"),
        ("reflog", "delete HEAD@{0}"),
        ("reflog", "drop --all"),
        ("reflog", "write"),
        ("reflog", "--textconv"),
        ("tag", "--list"),
        ("shortlog", "-sn"),
    ] {
        assert!(!read_form(subcommand, &args(rest)), "{subcommand} {rest}");
    }
}

#[test]
fn trailing_value_options_need_their_value() {
    for (subcommand, rest) in [
        ("blame", "--contents"),
        ("describe", "--match"),
        ("reflog", "--date"),
    ] {
        assert!(!read_form(subcommand, &args(rest)), "{subcommand} {rest}");
    }
}
