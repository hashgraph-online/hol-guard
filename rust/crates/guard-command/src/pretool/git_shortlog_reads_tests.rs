use super::read_form;

fn args(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn a_shortlog_narrowed_by_date_is_a_read_form() {
    for rest in [
        "--since=2.weeks",
        "-sn --since=2.weeks",
        "-sn --since=2.weeks HEAD",
        "-sne --since 2.weeks",
        "--after=2026-01-01 --until=2026-02-01",
        "--before 2026-02-01",
        "--since=3 --no-merges",
        "--since=2026-01-01T00:00:00+00:00",
    ] {
        assert!(read_form(&args(rest)), "shortlog {rest}");
    }
}

#[test]
fn a_date_bound_outside_the_date_grammar_keeps_its_review() {
    for rest in [
        "--since=%GG",
        "--since=$(cat .env)",
        "--since=",
        "--since",
        "--until=--format=%GS",
        "--before=`id`",
    ] {
        assert!(!read_form(&args(rest)), "shortlog {rest}");
    }
}
