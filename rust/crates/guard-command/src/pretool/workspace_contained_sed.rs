//! Sed may edit workspace files, but must not execute its input as commands.
use super::super::contained_wrapper::output_filters::sed_script::workspace_script;
/// Execution commands/flags are GNU sed extensions, so screen the GNU argv
/// interpretation. BSD sed rejects e rather than executing it; its separate
/// -i suffix must not make a valid GNU edit fail this execution screen.
/// Files and unknown options retain review because their scripts are unread.
pub(super) fn arguments_without_execution(arguments: &[String]) -> bool {
    let mut scripts = Vec::new();
    let mut positional = Vec::new();
    let mut index = 0;
    let mut options = true;
    while let Some(argument) = arguments.get(index) {
        index += 1;
        if options && argument == "--" {
            options = false;
            continue;
        }
        if !options || argument == "-" || !argument.starts_with('-') {
            positional.push(argument.as_str());
            continue;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let (name, value) = long
                .split_once('=')
                .map_or((long, None), |(n, v)| (n, Some(v)));
            match name {
                "expression" => {
                    let value = match value {
                        Some(v) => v,
                        None => {
                            let Some(v) = arguments.get(index) else {
                                return false;
                            };
                            index += 1;
                            v
                        }
                    };
                    scripts.push(value);
                }
                "in-place" => {}
                "quiet" | "silent" | "regexp-extended" | "separate" | "unbuffered"
                | "null-data" | "zero-terminated" | "posix" | "sandbox" | "debug"
                    if value.is_none() => {}
                _ => return false,
            }
            continue;
        }
        let flags = &argument[1..];
        for (offset, flag) in flags.char_indices() {
            match flag {
                'n' | 'E' | 'r' | 's' | 'u' | 'z' => {}
                'e' => {
                    let rest = &flags[offset + 1..];
                    let script = if rest.is_empty() {
                        let Some(v) = arguments.get(index) else {
                            return false;
                        };
                        index += 1;
                        v.as_str()
                    } else {
                        rest
                    };
                    scripts.push(script);
                    break;
                }
                'i' | 'I' => {
                    break;
                }
                _ => return false,
            }
        }
    }
    if scripts.is_empty() {
        let Some(script) = positional.first() else {
            return false;
        };
        scripts.push(script);
    }
    scripts.into_iter().all(workspace_script)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn safe(args: &[&str]) -> bool {
        arguments_without_execution(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }
    #[test]
    fn generic_workspace_admission_does_not_hide_sed_execution() {
        let ws = crate::pretool::workspace_contained_tests::workspace("sed-execution", true);
        for (command, expected) in [
            (
                r"cat README.md | sed -E 's/\/tmp\/scratch-[a-z0-9]+/TMPDIR/e'",
                false,
            ),
            ("sed -e 'e rm tracked.txt' README.md", false),
            ("sed --expression='s/a/b/e' README.md", false),
            ("sed -ne's/a/b/e' README.md", false),
            ("sed -f commands.sed README.md", false),
            ("sed -i '' -e 's/a/b/g' README.md", true),
            ("sed -i.bak 's/a/b/g' README.md", true),
            ("sed -n '1,5p' README.md", true),
        ] {
            let model = crate::parse_command(&crate::CommandModelRequestV1 {
                command: command.into(),
                dialect: "posix".into(),
                transport: "shell_string".into(),
                extraction_provenance: "pre-tool-generic".into(),
            })
            .unwrap();
            assert_eq!(
                super::super::command_shape(&model, &ws, Some(command)).is_some(),
                expected,
                "{command}"
            );
        }
        let _ = std::fs::remove_dir_all(ws);
    }
    #[test]
    fn execution_stays_reviewed_in_every_script_position() {
        assert!(arguments_without_execution(
            &["-i", "s/a/b/", "file"].map(String::from)
        ));
        for args in [
            vec!["-E", r"s/\/tmp\/scratch-[a-z0-9]+/TMPDIR/e"],
            vec!["-e", "s/a/b/e"],
            vec!["--expression=s/a/b/e"],
            vec!["-nes/a/b/e"],
            vec!["e rm tracked.txt"],
            vec!["-i", "s/a/b/e", "file"],
            vec!["-nf", "script"],
            vec!["--file=script"],
            vec!["--exp=s/a/b/e"],
            vec!["-e", "s/a/b/", "-e", "e rm tracked.txt"],
            vec!["w output\ne rm tracked.txt"],
        ] {
            assert!(!safe(&args), "{args:?}");
        }
    }
    #[test]
    fn workspace_file_effects_and_literal_letters_remain_supported() {
        for args in [
            vec!["-E", "s/a/e/g", "file"],
            vec!["-n", "1,5p", "file"],
            vec!["-i", "", "s/a/b/", "file"],
            vec!["-i.bak", "s/a/b/", "file"],
            vec!["-i", "-e", "s/a/b/", "file"],
            vec!["s/a/b/w output; e literal-filename"],
            vec!["r input; e literal-filename"],
            vec!["a e literal-text"],
        ] {
            assert!(safe(&args), "{args:?}");
        }
    }
}
