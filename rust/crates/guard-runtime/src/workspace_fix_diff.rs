//! Unified diff of a manifest edit.
//!
//! A fix edit only rewrites characters inside a string, so the before and after
//! texts always have the same lines and a line either changed or did not. The
//! output follows `diff -u` with three lines of context.

const CONTEXT: usize = 3;

/// Lines of `text`, each keeping its `\n`. Only `\n` ends a line, so a form
/// feed or a Unicode separator inside a JSON string stays in its line.
fn lines(text: &str) -> Vec<&str> {
    text.split_inclusive('\n').collect()
}

fn range(start: usize, length: usize) -> String {
    match length {
        1 => format!("{}", start + 1),
        0 => format!("{start},0"),
        _ => format!("{},{length}", start + 1),
    }
}

fn push_line(output: &mut String, marker: char, line: &str) {
    output.push(marker);
    output.push_str(line);
    if !line.ends_with('\n') {
        output.push_str("\n\\ No newline at end of file\n");
    }
}

/// The diff from `before` to `after`, or an empty string when they are equal.
pub(crate) fn unified_diff(before: &str, after: &str, relative_path: &str) -> String {
    let old = lines(before);
    let new = lines(after);
    let changed: Vec<usize> = if old.len() == new.len() {
        (0..old.len())
            .filter(|&index| old[index] != new[index])
            .collect()
    } else {
        // Not reachable for spec edits; replace the whole file rather than guess.
        Vec::new()
    };
    let mut hunks: Vec<(usize, usize)> = Vec::new();
    if old.len() == new.len() {
        for index in changed {
            match hunks.last_mut() {
                Some(last) if index <= last.1 + 2 * CONTEXT => last.1 = index,
                _ => hunks.push((index, index)),
            }
        }
    } else if before != after {
        let mut output = format!("--- a/{relative_path}\n+++ b/{relative_path}\n");
        output.push_str(&format!(
            "@@ -{} +{} @@\n",
            range(0, old.len()),
            range(0, new.len())
        ));
        old.iter()
            .for_each(|line| push_line(&mut output, '-', line));
        new.iter()
            .for_each(|line| push_line(&mut output, '+', line));
        return output;
    }
    if hunks.is_empty() {
        return String::new();
    }
    let mut output = format!("--- a/{relative_path}\n+++ b/{relative_path}\n");
    for (first, last) in hunks {
        let start = first.saturating_sub(CONTEXT);
        let end = (last + 1 + CONTEXT).min(old.len());
        output.push_str(&format!(
            "@@ -{} +{} @@\n",
            range(start, end - start),
            range(start, end - start)
        ));
        for index in start..end {
            if old[index] == new[index] {
                push_line(&mut output, ' ', old[index]);
            } else {
                push_line(&mut output, '-', old[index]);
                push_line(&mut output, '+', new[index]);
            }
        }
    }
    output
}

#[cfg(test)]
#[path = "workspace_fix_diff_tests.rs"]
mod tests;
