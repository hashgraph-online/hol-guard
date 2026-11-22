//! A line break behind another separator continues the list it is in.
use super::split_execution_segments;

/// Agents write their shell across lines. `A;` followed by a line break is one
/// ending, not two, and `A &&`, `A ||` and `A |` carry the list onto the line
/// below them. Reading the blank span between the two as a command of its own
/// left every multi-line command unmodelled, which cost it every proof the
/// parsed segments carry -- containment among them.
#[test]
fn a_line_break_behind_a_separator_does_not_end_a_command_of_its_own() {
    for (command, words) in [
        ("npm test;\n echo done", vec!["npm test", "echo done"]),
        ("npm test ;\n\n echo done", vec!["npm test", "echo done"]),
        ("npm test &&\n echo done", vec!["npm test", "echo done"]),
        ("npm test ||\n echo failed", vec!["npm test", "echo failed"]),
        ("npm test |\n tail -5", vec!["npm test", "tail -5"]),
        ("\nnpm test", vec!["npm test"]),
        ("npm test\n\necho done", vec!["npm test", "echo done"]),
    ] {
        let chars: Vec<char> = command.chars().collect();
        let segments = split_execution_segments(command, false)
            .unwrap_or_else(|reason| panic!("{command:?}: {reason}"));
        let read: Vec<String> = segments
            .iter()
            .map(|segment| chars[segment.start..segment.end].iter().collect())
            .collect();
        assert_eq!(read, words, "{command:?}");
    }
}

/// The line-break spelling is the only one that may stand on an empty span.
/// `A; ; B` and a `;` opening a line are syntax errors the shell refuses to
/// run, and a list left hanging on `|`, `&&` or `||` names no command at all.
#[test]
fn an_empty_span_between_other_separators_is_still_not_a_command() {
    for command in [
        "npm test; ; echo done",
        "npm test\n; echo done",
        "npm test |\n",
        "npm test &&\n",
        "; npm test",
    ] {
        assert!(
            split_execution_segments(command, false).is_err(),
            "{command:?}"
        );
    }
}

/// The pipeline the line break spans is still one pipeline. A stage written on
/// the next line belongs to the group in front of it, so the filter chain a
/// multi-line pipeline spells reads the same as the one written on one line.
#[test]
fn a_pipeline_keeps_its_shape_across_a_line_break() {
    let flat = split_execution_segments("npm test 2>&1 | grep err | tail -5", false).unwrap();
    let broken =
        split_execution_segments("npm test 2>&1 |\n  grep err |\n  tail -5", false).unwrap();
    let shape = |segments: &[super::RawSegment]| -> Vec<(usize, usize)> {
        segments
            .iter()
            .map(|segment| (segment.group_index, segment.pipeline_index))
            .collect()
    };
    assert_eq!(shape(&broken), shape(&flat));
}
