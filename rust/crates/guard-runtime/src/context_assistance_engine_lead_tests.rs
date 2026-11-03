use super::*;

fn file(path: &str, chunks: &[(&str, u32)]) -> AdmittedFile {
    AdmittedFile {
        source_id: format!("source:{path}"),
        relative_path: path.into(),
        sha256: String::new(),
        documents: chunks
            .iter()
            .enumerate()
            .map(|(index, (text, start_line))| ContextDocument {
                id: format!("doc:{path}:{index}"),
                text: (*text).into(),
                start_line: *start_line,
            })
            .collect(),
    }
}

fn picked(path: &str) -> PickedExcerpt {
    PickedExcerpt {
        path: path.into(),
        start_line: 194,
        end_line: 203,
        text: "<button>Cancel</button>".into(),
    }
}

/// The walk's words for "The confirm dialog's default cancel button should
/// say "Never mind" instead of "Cancel"", quoted text last.
fn prompt() -> Vec<String> {
    [
        "confirm",
        "dialog",
        "default",
        "cancel",
        "button",
        "say",
        "instead",
        "never mind",
    ]
    .map(String::from)
    .to_vec()
}

/// CIGAR picked other files that mention a cancel button; the file the walk
/// ranked first leads with its chunk that holds the button.
#[test]
fn the_walks_best_file_leads_when_cigar_left_it_out() {
    let dialog = file(
        "src/confirm-dialog.tsx",
        &[
            (
                "import { useState } from 'react';\nexport type Props = {};\n",
                1,
            ),
            (
                "export function ConfirmDialog() {\n  return <button>Cancel</button>;\n}\n",
                3,
            ),
        ],
    );
    let led = led_by(
        vec![picked("src/data-repair-panel.tsx")],
        Some(&dialog),
        &prompt(),
    );
    assert_eq!(led[0].path, "src/confirm-dialog.tsx");
    assert_eq!((led[0].start_line, led[0].end_line), (3, 5));
    assert!(led[0].text.contains("<button>Cancel</button>"));
    assert_eq!(led[1].path, "src/data-repair-panel.tsx");
}

#[test]
fn cigars_own_picks_stand_when_they_hold_the_file_or_it_says_nothing_relevant() {
    let dialog = file("src/confirm-dialog.tsx", &[("export const a = 1;\n", 1)]);
    let kept = led_by(
        vec![picked("src/confirm-dialog.tsx")],
        Some(&dialog),
        &prompt(),
    );
    assert_eq!(kept.len(), 1);
    let unrelated = led_by(vec![picked("src/other.tsx")], Some(&dialog), &prompt());
    assert_eq!(unrelated.len(), 1);
    assert_eq!(unrelated[0].path, "src/other.tsx");
    assert_eq!(led_by(Vec::new(), None, &prompt()).len(), 0);
}

/// The walk's words come from the whole prompt, so quoted text past the
/// part CIGAR was asked about still finds its chunk.
#[test]
fn a_chunk_holding_only_the_quoted_text_still_leads() {
    let labels = file(
        "src/labels.ts",
        &[
            ("export const title = 'Delete';\n", 1),
            ("export const back = 'never mind';\n", 2),
        ],
    );
    let words = vec!["never mind".to_owned()];
    let led = led_by(Vec::new(), Some(&labels), &words);
    assert_eq!(led.len(), 1);
    assert_eq!(led[0].start_line, 2);
}
