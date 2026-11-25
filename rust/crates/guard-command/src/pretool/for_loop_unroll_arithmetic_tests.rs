use super::evaluated_bodies;

fn bodies(rest: &str, words: &[&str]) -> Option<Option<Vec<String>>> {
    let words: Vec<String> = words.iter().map(|word| word.to_string()).collect();
    evaluated_bodies(rest, "n", &words)
}

#[test]
fn each_pass_writes_out_the_value_of_the_expansion() {
    assert_eq!(
        bodies(r#" sed -n "$n,$((n+6))p" job.log; done"#, &["5315", "40"]),
        Some(Some(vec![
            r#" sed -n "$n,5321p" job.log; done"#.to_string(),
            r#" sed -n "$n,46p" job.log; done"#.to_string(),
        ]))
    );
    assert_eq!(
        bodies(" head -n $(( $n * 2 - 1 )) a.md; done", &["3"]),
        Some(Some(vec![" head -n 5 a.md; done".to_string()]))
    );
    assert_eq!(bodies(" sed -n 1,${n}p a.md; done", &["x"]), Some(None));
}

#[test]
fn other_arithmetic_keeps_its_review() {
    for (rest, words) in [
        (" echo $((n++)); done", &["1"][..]),
        (" echo $((m+1)); done", &["1"]),
        (" echo $((n/2)); done", &["4"]),
        (" echo $((-n)); done", &["4"]),
        (" echo $((n+1)); done", &["a"]),
        (" echo $((n+1)); done", &["08"]),
        (" echo $((n+$(id -u))); done", &["1"]),
        (" echo $((n+1); done", &["1"]),
        (" echo $((n+999999999*999999999*999999999)); done", &["1"]),
    ] {
        assert_eq!(bodies(rest, words), None, "{rest}");
    }
}

#[test]
fn single_quotes_and_escapes_are_left_alone() {
    assert_eq!(
        bodies(r#" awk '{print $((n))}' a; echo \$((n)); done"#, &["1"]),
        Some(Some(vec![
            r#" awk '{print $((n))}' a; echo \$((n)); done"#.to_string()
        ]))
    );
}

#[test]
fn an_apostrophe_inside_double_quotes_opens_no_single_quoted_span() {
    // The shell reads `'part$((n+1)).md'` as literal text, so the written pass
    // must keep it, while the expansion inside double quotes is evaluated.
    assert_eq!(
        bodies(
            r#" echo "it's $((n+1))"; cat 'part$((n+1)).md'; done"#,
            &["1"]
        ),
        Some(Some(vec![
            r#" echo "it's 2"; cat 'part$((n+1)).md'; done"#.to_string()
        ]))
    );
}

#[test]
fn a_header_past_the_word_bound_writes_out_no_pass() {
    let words: Vec<String> = (0..=super::super::MAX_WORDS)
        .map(|n| n.to_string())
        .collect();
    assert_eq!(evaluated_bodies(" echo $((n+1)); done", "n", &words), None);
}
