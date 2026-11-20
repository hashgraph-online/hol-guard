use super::{filter_tail, split};

#[test]
fn a_leading_group_piped_into_filters_splits_into_its_list_and_filters() {
    assert_eq!(
        split("{ echo a; echo b; } | head -100"),
        Some(("echo a; echo b".to_owned(), "head -100".to_owned()))
    );
    assert_eq!(
        split("{ rg -l x a.ts; rg -l x b.ts; } | sort | uniq -c"),
        Some((
            "rg -l x a.ts; rg -l x b.ts".to_owned(),
            "sort | uniq -c".to_owned()
        ))
    );
    assert_eq!(
        split("{ echo a; } | jq -r '.a | .b'"),
        Some(("echo a".to_owned(), "jq -r '.a | .b'".to_owned()))
    );
}

#[test]
fn a_consumer_that_runs_or_opens_its_input_keeps_the_group_whole() {
    for command in [
        "{ ls docs; ls src; } | xargs cat",
        "{ echo a; echo b; } | sh",
        "{ echo a; echo b; } | while read l; do cat \"$l\"; done",
        "{ echo a; echo b; } | head > out.txt",
        "{ echo a; echo b; } | head; rm -rf build",
        "{ echo a; echo b; } || head",
        "{ echo a; echo b; } | head | $PAGER",
        "{ echo a; echo b; } | grep \"$(cat ~/.ssh/id_rsa)\"",
        "{ echo a; echo b; } | tee out.txt",
        "{ echo a; echo b; } | head &",
    ] {
        assert_eq!(split(command), None, "{command}");
    }
}

#[test]
fn only_a_group_that_opens_the_command_is_read() {
    for command in [
        "cd web && { echo a; echo b; } | head",
        "{ echo a; echo b } | head",
        "{echo a; echo b; } | head",
        "{ echo a; echo b; }",
        "{ echo a; } | head; { echo b; } | head",
    ] {
        assert_eq!(split(command), None, "{command}");
    }
}

#[test]
fn a_loop_tail_is_read_only_as_a_pipe_into_filters() {
    assert_eq!(filter_tail(" | head -100"), Some("head -100".to_owned()));
    assert_eq!(
        filter_tail(" | sort | uniq -c"),
        Some("sort | uniq -c".to_owned())
    );
    for tail in ["", " > out", " || echo x", " | xargs rm", " | head > out"] {
        assert_eq!(filter_tail(tail), None, "{tail:?}");
    }
}

#[test]
fn the_filters_stay_in_the_model_extension_controls_read() {
    let root = env!("CARGO_MANIFEST_DIR");
    let request = super::super::CommandModelRequestV1 {
        command: "{ echo a; echo b; } | sort".to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    };
    let decision =
        super::super::evaluate_pre_tool_with_context(&request, Some(root), Some(root)).unwrap();
    assert_eq!(decision.minimum_action, "allow");
    let executables: Vec<_> = decision
        .command_model
        .segments
        .iter()
        .filter_map(|segment| segment.executable.as_deref())
        .collect();
    assert!(executables.contains(&"sort"), "{executables:?}");
    assert!(executables.contains(&"echo"), "{executables:?}");
    assert!(!executables.contains(&"printf"), "{executables:?}");
}
