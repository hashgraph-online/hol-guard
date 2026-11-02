use super::listing;

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn plain_origin_listing_is_a_listing() {
    assert!(listing(&arguments(&["origin"])));
    assert!(listing(&arguments(&["--heads", "origin"])));
    assert!(listing(&arguments(&["--heads", "origin", "main"])));
    assert!(listing(&arguments(&["--tags", "--refs", "origin"])));
    assert!(listing(&arguments(&[
        "-q",
        "--exit-code",
        "origin",
        "refs/heads/*"
    ])));
    assert!(listing(&arguments(&[
        "--symref",
        "--sort=-committerdate",
        "origin"
    ])));
    assert!(listing(&arguments(&["origin", "--", "main"])));
}

#[test]
fn a_listing_names_origin() {
    assert!(!listing(&arguments(&[])));
    assert!(!listing(&arguments(&["--heads"])));
    assert!(!listing(&arguments(&["upstream"])));
    assert!(!listing(&arguments(&[
        "https://github.com/example-org/service.git"
    ])));
    assert!(!listing(&arguments(&["../sibling"])));
}

#[test]
fn an_option_that_runs_a_program_keeps_the_review() {
    assert!(!listing(&arguments(&[
        "--upload-pack=touch /tmp/marker",
        "origin"
    ])));
    assert!(!listing(&arguments(&["-u", "touch /tmp/marker", "origin"])));
    assert!(!listing(&arguments(&["-o", "option", "origin"])));
    assert!(!listing(&arguments(&["--server-option=option", "origin"])));
    assert!(!listing(&arguments(&["--sort=committerdate;id", "origin"])));
    assert!(!listing(&arguments(&["--sort=", "origin"])));
}

#[test]
fn an_operand_that_is_not_a_ref_pattern_keeps_the_review() {
    assert!(!listing(&arguments(&["origin", "../outside"])));
    assert!(!listing(&arguments(&["origin", "main..next"])));
    assert!(!listing(&arguments(&["origin", ""])));
}

#[test]
fn more_patterns_than_the_bound_keeps_the_review() {
    let mut values = vec!["origin".to_owned()];
    values.extend((0..8).map(|_| "main".to_owned()));
    assert!(listing(&values));
    values.push("next".to_owned());
    assert!(!listing(&values));
}

#[test]
fn a_second_remote_is_read_as_a_pattern() {
    // Git treats everything after the remote as a pattern, and so does this.
    assert!(listing(&arguments(&["origin", "upstream"])));
}
