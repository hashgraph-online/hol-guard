//! Safety checks for a read-only `jq` output processor.

const FILE_OPTIONS: [&str; 8] = [
    "-f",
    "-L",
    "--argfile",
    "--from-file",
    "--library-path",
    "--rawfile",
    "--run-tests",
    "--slurpfile",
];
const SAFE_SHORT_OPTION_CHARACTERS: &str = "RacenrSsjMC";
const SAFE_LONG_OPTIONS: [&str; 13] = [
    "--ascii-output",
    "--compact-output",
    "--exit-status",
    "--join-output",
    "--monochrome-output",
    "--null-input",
    "--raw-input",
    "--raw-output",
    "--seq",
    "--slurp",
    "--sort-keys",
    "--tab",
    "--unbuffered",
];

/// One filter, preceded only by output-shaping options, and no file inputs.
pub(super) fn safe_jq_arguments(arguments: &[String]) -> bool {
    let mut filter_seen = false;
    for argument in arguments {
        let argument = argument.as_str();
        if FILE_OPTIONS.contains(&argument)
            || argument.starts_with("-L")
            || FILE_OPTIONS.iter().any(|option| {
                argument
                    .strip_prefix(option)
                    .is_some_and(|rest| rest.starts_with('='))
            })
        {
            return false;
        }
        if !filter_seen && SAFE_LONG_OPTIONS.contains(&argument) {
            continue;
        }
        if !filter_seen
            && argument.chars().count() > 1
            && argument.strip_prefix('-').is_some_and(|flags| {
                flags
                    .chars()
                    .all(|character| SAFE_SHORT_OPTION_CHARACTERS.contains(character))
            })
        {
            continue;
        }
        if argument.starts_with('-') || filter_seen {
            return false;
        }
        filter_seen = true;
    }
    filter_seen
}
