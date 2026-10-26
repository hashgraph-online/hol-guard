//! `git ls-tree` and `git cat-file` forms that only print repository objects.
//!
//! `ls-tree` lists tree entries; no option starts a helper. `cat-file` is
//! admitted only for `-t`, `-s`, `-e`, `-p` and `<type> <object>`:
//! `--textconv`, `--filters` and `--path` run configured textconv or filter
//! drivers, and the `--batch*` modes read their object names from stdin, so
//! those keep their review. Both still honor `pager.<name>`, and a partial
//! clone can fetch a missing object, so the configuration probe clears the
//! read before it is proven. Revision and path operands pass the shared
//! sensitive-path screen like `git show`.

/// Whether `subcommand rest...` is a proven object read.
pub(crate) fn read_form(subcommand: &str, rest: &[String]) -> bool {
    match subcommand {
        "ls-tree" => ls_tree_read(rest),
        "cat-file" => cat_file_read(rest),
        _ => false,
    }
}

fn operand(value: &str) -> bool {
    !value.is_empty() && !value.starts_with('-')
}

fn ls_tree_read(rest: &[String]) -> bool {
    let mut operands = 0;
    let mut options_done = false;
    for argument in rest {
        let value = argument.as_str();
        if options_done || operand(value) {
            operands += 1;
            continue;
        }
        if value == "--" {
            options_done = true;
            continue;
        }
        let abbrev = value
            .strip_prefix("--abbrev=")
            .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()));
        let short_flags = value.strip_prefix('-').is_some_and(|flags| {
            !flags.is_empty() && flags.chars().all(|flag| "drtlz".contains(flag))
        });
        // The format only selects which entry fields are printed.
        let known = abbrev
            || short_flags
            || value.starts_with("--format=")
            || matches!(
                value,
                "--long"
                    | "--name-only"
                    | "--name-status"
                    | "--object-only"
                    | "--full-name"
                    | "--full-tree"
                    | "--abbrev"
            );
        if !known {
            return false;
        }
    }
    // The tree-ish is required; the rest are paths inside it.
    operands > 0
}

fn cat_file_read(rest: &[String]) -> bool {
    let [mode, object] = rest else {
        return false;
    };
    matches!(
        mode.as_str(),
        "-t" | "-s" | "-e" | "-p" | "blob" | "tree" | "commit" | "tag"
    ) && operand(object)
}

#[cfg(test)]
mod tests {
    fn admitted(text: &str) -> bool {
        let arguments: Vec<String> = text.split_whitespace().map(str::to_owned).collect();
        super::read_form(&arguments[0], &arguments[1..])
    }

    #[test]
    fn object_reads_follow_the_option_model() {
        for text in [
            "ls-tree HEAD",
            "ls-tree HEAD --name-only src/",
            "ls-tree -r HEAD",
            "ls-tree -rtz --abbrev=8 HEAD -- src",
            "ls-tree --format=%(objectname) HEAD",
            "cat-file -p HEAD:README.md",
            "cat-file -t HEAD",
            "cat-file blob HEAD:README.md",
        ] {
            assert!(admitted(text), "{text}");
        }
        for text in [
            "ls-tree",
            "ls-tree --name-only",
            "ls-tree -x HEAD",
            "ls-tree --format HEAD",
            "cat-file --textconv HEAD:README.md",
            "cat-file --filters HEAD:README.md",
            "cat-file --path=README.md blob HEAD",
            "cat-file --batch",
            "cat-file --batch-check",
            "cat-file --batch-all-objects --batch-check",
            "cat-file -p",
            "cat-file -p HEAD extra",
            "cat-file -p --textconv",
            "cat-file -P HEAD",
            "cat-file other HEAD",
        ] {
            assert!(!admitted(text), "{text}");
        }
    }
}
