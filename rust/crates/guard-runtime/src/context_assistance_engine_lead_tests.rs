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

const PROMPT: &str =
    "The confirm dialog's default cancel button should say \"Never mind\" instead of \"Cancel\".";

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
        PROMPT,
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
        PROMPT,
    );
    assert_eq!(kept.len(), 1);
    let unrelated = led_by(vec![picked("src/other.tsx")], Some(&dialog), PROMPT);
    assert_eq!(unrelated.len(), 1);
    assert_eq!(unrelated[0].path, "src/other.tsx");
    assert_eq!(led_by(Vec::new(), None, PROMPT).len(), 0);
}
