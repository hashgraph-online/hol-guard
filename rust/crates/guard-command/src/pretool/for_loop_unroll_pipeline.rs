//! The pipeline stages of one `for` body item.

/// The pipeline stages of a body item, cut at the `|` characters the shell
/// reads as stage separators.
///
/// A `|` written inside quotes is text the command receives as part of one
/// word rather than a separator: `--jq '.a | select(.b == "x")'` hands jq a
/// filter the shell never looks inside. Cutting the raw characters invents a
/// stage the pipeline never had and reads the tail of that quoted word as a
/// command word, so a filter holding `=` or a glob character kept an ordinary
/// read on the unmodeled path. Only an unquoted, unescaped `|` cuts here.
///
/// Quotes left open spell a command the shell refuses to run, and the state
/// this scan carries says nothing about where its stages are, so an item that
/// ends inside a quoted run is reported as no stages at all and keeps its
/// review.
pub(super) fn pipeline_stages(item: &str) -> Option<Vec<&str>> {
    let chars: Vec<char> = item.chars().collect();
    let offsets: Vec<usize> = item.char_indices().map(|(offset, _)| offset).collect();
    let mut stages = Vec::new();
    let mut start = 0usize;
    let mut single = false;
    let mut double = false;
    for (index, &current) in chars.iter().enumerate() {
        match current {
            '\'' if !double && (single || !super::escaped(&chars, index)) => single = !single,
            '"' if !single && !super::escaped(&chars, index) => double = !double,
            '|' if !single && !double && !super::escaped(&chars, index) => {
                stages.push(&item[start..offsets[index]]);
                start = offsets[index] + 1;
            }
            _ => {}
        }
    }
    if single || double {
        return None;
    }
    stages.push(&item[start..]);
    Some(stages)
}
