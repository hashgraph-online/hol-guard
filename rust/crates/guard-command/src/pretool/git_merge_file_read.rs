//! Closed grammar for a `git merge-file` invocation that prints its result.
//!
//! `git merge-file` runs a three-way merge of three files. Without
//! `-p`/`--stdout` it writes the merged text over the first file it was
//! named. With either flag it writes nothing and prints the merge, so it reads
//! the three files and nothing else. `--object-id` reads blobs out of the
//! object store instead of files and stays outside the grammar, as does every
//! option it does not name.

/// The three files a proven printing merge reads, or `None` when the
/// invocation is no proven printing merge. `arguments` are the tokens after
/// the `merge-file` subcommand.
pub(crate) fn read_targets(arguments: &[String]) -> Option<Vec<&str>> {
    let mut printing = false;
    let mut labels = 0;
    let mut operands_only = false;
    let mut operands = Vec::new();
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        index += 1;
        if operands_only || !argument.starts_with('-') || argument == "-" {
            operands.push(argument.as_str());
            continue;
        }
        match argument.as_str() {
            "--" => operands_only = true,
            "-p" | "--stdout" => printing = true,
            "-q" | "--quiet" | "--diff3" | "--zdiff3" | "--ours" | "--theirs" | "--union" => {}
            "-L" => {
                // A label only names a side in the conflict markers it prints.
                arguments.get(index)?;
                index += 1;
                labels += 1;
            }
            value => {
                if let Some(size) = value.strip_prefix("--marker-size=") {
                    if size.is_empty()
                        || size.len() > 4
                        || !size.bytes().all(|b| b.is_ascii_digit())
                    {
                        return None;
                    }
                } else if let Some(algorithm) = value.strip_prefix("--diff-algorithm=") {
                    if !matches!(
                        algorithm,
                        "myers" | "default" | "minimal" | "patience" | "histogram"
                    ) {
                        return None;
                    }
                } else if value.len() > 2 && value.starts_with("-L") && !value.starts_with("--") {
                    labels += 1;
                } else {
                    return None;
                }
            }
        }
    }
    (printing
        && labels <= 3
        && operands.len() == 3
        && operands
            .iter()
            .all(|operand| super::git_apply_check::plain_path(operand)))
    .then_some(operands)
}

/// Whether the invocation only prints a merge of three plainly named files.
pub(crate) fn is_read_only(arguments: &[String]) -> bool {
    read_targets(arguments).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn a_printing_merge_of_three_files_reads_them() {
        for text in [
            "-p a.ts b.ts c.ts",
            "--stdout a.ts b.ts c.ts",
            "-p --diff3 -L ours -L base -L theirs a.ts b.ts c.ts",
            "-q -p --zdiff3 --marker-size=9 --diff-algorithm=histogram a.ts b.ts c.ts",
            "-p --union -- a.ts b.ts c.ts",
            "-p -Lmine src/a.ts /work/b.ts c.ts",
        ] {
            assert_eq!(
                read_targets(&words(text)).map(|t| t.len()),
                Some(3),
                "{text}"
            );
        }
    }

    #[test]
    fn a_merge_that_writes_or_reaches_further_is_not_a_read() {
        for text in [
            "a.ts b.ts c.ts",
            "--diff3 a.ts b.ts c.ts",
            "-p a.ts b.ts",
            "-p a.ts b.ts c.ts d.ts",
            "-p --object-id a b c",
            "-p a.ts ../b.ts c.ts",
            "-p - b.ts c.ts",
            "-p a.ts b.ts *.ts",
            "-p --marker-size=x a.ts b.ts c.ts",
            "-p --diff-algorithm=other a.ts b.ts c.ts",
            "-p -L a -L b -L c -L d a.ts b.ts c.ts",
            "-p -L",
            "-p --output=x a.ts b.ts c.ts",
        ] {
            assert!(read_targets(&words(text)).is_none(), "{text}");
        }
    }
}
