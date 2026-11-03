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

fn excerpt(path: &str, lines: (u64, u64), text: &str) -> PickedExcerpt {
    PickedExcerpt {
        path: path.into(),
        start_line: lines.0,
        end_line: lines.1,
        text: text.into(),
    }
}

/// "In the service recovery instructions, change "Restart Guard" to "Restart
/// HOL Guard" in the native recovery step": CIGAR picked the right file but
/// the lines after the step, which only mention restarting Guard in passing.
#[test]
fn the_chunk_the_prompt_quotes_joins_a_pick_of_the_same_file_that_missed_it() {
    let recovery = file(
        "src/service-recovery.ts",
        &[
            (
                "steps: [\"Choose Restart Guard in the native recovery screen.\"],\n",
                210,
            ),
            (
                "body: \"A tab cannot restart Guard through a service.\",\n",
                231,
            ),
        ],
    );
    let words: Vec<String> = [
        "service",
        "recovery",
        "restart",
        "guard",
        "native",
        "restart guard",
    ]
    .map(String::from)
    .to_vec();
    let cigar = excerpt(
        "src/service-recovery.ts",
        (230, 273),
        "body: \"A tab cannot restart Guard through the recovery service.\",\n",
    );
    let led = led_by(vec![cigar], Some(&recovery), &words);
    assert_eq!(led.len(), 2);
    assert_eq!((led[0].start_line, led[0].end_line), (210, 210));
    assert!(led[0].text.contains("Choose Restart Guard"));
    assert_eq!(led[1].start_line, 230);
}

#[test]
fn a_pick_that_overlaps_the_chunk_or_holds_more_of_the_prompt_stands_alone() {
    let recovery = file(
        "src/service-recovery.ts",
        &[("Choose Restart in the native screen.\n", 210)],
    );
    let words: Vec<String> = ["restart", "guard", "native", "restart guard"]
        .map(String::from)
        .to_vec();
    let overlapping = excerpt("src/service-recovery.ts", (205, 215), "steps");
    assert_eq!(
        led_by(vec![overlapping], Some(&recovery), &words).len(),
        1,
        "CIGAR already shows those lines"
    );
    let richer = excerpt(
        "src/service-recovery.ts",
        (300, 320),
        "restart guard native recovery restart",
    );
    let led = led_by(vec![richer], Some(&recovery), &words);
    assert_eq!(led.len(), 1, "CIGAR's pick holds more of the prompt");
    assert_eq!(led[0].start_line, 300);
}
