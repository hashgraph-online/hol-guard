use super::without_jq_filter;

fn segment(command: &str, stage: usize) -> crate::CommandSegmentV1 {
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap()
    .segments
    .swap_remove(stage)
}

#[test]
fn a_single_quoted_filter_is_blanked_and_the_rest_is_kept() {
    let step = segment(
        "gh run list --json t | jq -c '.[] | select(.t | test(\"secret-blast\"))' -",
        1,
    );
    assert_eq!(without_jq_filter(&step, 1).as_deref(), Some("jq -c '' -"));
    let file = segment("jq '.password' ~/.secrets/app.json", 0);
    assert_eq!(
        without_jq_filter(&file, 0).as_deref(),
        Some("jq '' ~/.secrets/app.json")
    );
}

#[test]
fn any_other_spelling_keeps_the_whole_text() {
    for (command, index) in [
        // Double quotes, no quotes, or a word the shell joins to more text.
        ("jq \".secret\" a.json", 0),
        ("jq .secret a.json", 0),
        ("jq x'.secret' a.json", 0),
        // The same quoted word twice: which one is the filter is not known.
        ("jq '.secret' '.secret'", 0),
        ("jq --arg k '.secret' '.secret'", 3),
        // The quoted copy sits inside a double-quoted `--arg` value; the
        // filter itself is spelled another way.
        ("jq -n --arg note \" '.secret' \" .se''cret", 4),
    ] {
        let step = segment(command, 0);
        assert_eq!(without_jq_filter(&step, index), None, "{command}");
    }
}
