use super::*;

#[test]
fn lines_split_at_every_boundary_python_reads() {
    assert_eq!(
        split_lines_keepends("a\r\nb\rc\x0bd\u{2028}e\u{85}f\x1cg"),
        [
            "a\r\n",
            "b\r",
            "c\x0b",
            "d\u{2028}",
            "e\u{85}",
            "f\x1c",
            "g"
        ]
    );
    assert_eq!(split_lines_keepends("\n\n"), ["\n", "\n"]);
    assert!(split_lines_keepends("").is_empty());
}

#[test]
fn slices_clamp_like_python_slicing() {
    let text = "1\n2\n3\n";
    let leading = VerifiedReadSelectionV1::LeadingLines { count: 9 };
    let trailing = VerifiedReadSelectionV1::TrailingLines { count: 2 };
    let range = VerifiedReadSelectionV1::LineRange { start: 5, end: 9 };
    assert_eq!(selected(text, &leading), text);
    assert_eq!(selected(text, &trailing), "2\n3\n");
    assert_eq!(selected(text, &range), "");
    assert_eq!(selected("", &leading), "");
}

#[test]
fn every_selection_names_the_same_lines_the_whole_split_would() {
    let texts = [
        "",
        "only",
        "1\n2\n3\n",
        "1\n2\n3",
        "a\r\nb\rc\x0bd\u{2028}e",
        "\n\n\n",
    ];
    let selections = [
        VerifiedReadSelectionV1::WorkingDirectory {},
        VerifiedReadSelectionV1::LeadingLines { count: 0 },
        VerifiedReadSelectionV1::LeadingLines { count: 2 },
        VerifiedReadSelectionV1::LeadingLines { count: 99 },
        VerifiedReadSelectionV1::TrailingLines { count: 0 },
        VerifiedReadSelectionV1::TrailingLines { count: 2 },
        VerifiedReadSelectionV1::TrailingLines { count: 99 },
        VerifiedReadSelectionV1::LineRange { start: 1, end: 1 },
        VerifiedReadSelectionV1::LineRange { start: 2, end: 3 },
        VerifiedReadSelectionV1::LineRange { start: 3, end: 2 },
        VerifiedReadSelectionV1::LineRange { start: 9, end: 9 },
    ];
    for text in texts {
        let lines = split_lines_keepends(text);
        for selection in &selections {
            assert_eq!(
                selected(text, selection),
                whole_split(&lines, selection).concat(),
                "{text:?} {selection:?}"
            );
        }
    }
}

/// The selection as the first implementation expressed it: slice a vector
/// holding every line of the file.
fn whole_split<'a>(lines: &[&'a str], selection: &VerifiedReadSelectionV1) -> Vec<&'a str> {
    let total = lines.len();
    let (from, to) = match selection {
        VerifiedReadSelectionV1::WorkingDirectory {} => (0, 0),
        VerifiedReadSelectionV1::LeadingLines { count } => (0, total.min(*count as usize)),
        VerifiedReadSelectionV1::TrailingLines { count } => {
            (total.saturating_sub(*count as usize), total)
        }
        VerifiedReadSelectionV1::LineRange { start, end } => (
            total.min((*start as usize).saturating_sub(1)),
            total.min(*end as usize),
        ),
    };
    lines[from..to.max(from)].to_vec()
}
