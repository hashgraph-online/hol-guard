use super::*;

fn rows(text: &str, script_source: bool) -> Vec<LocalCliCommand> {
    variations(text, &["tool.sh".to_owned()], script_source)
}

fn ids(text: &str, script_source: bool) -> Vec<String> {
    rows(text, script_source)
        .into_iter()
        .map(|row| row.command_id)
        .collect()
}

fn usage_of(found: &[LocalCliCommand], id: &str) -> String {
    found
        .iter()
        .find(|row| row.command_id == id)
        .unwrap_or_else(|| panic!("{id} missing"))
        .usage
        .clone()
}

/// The shape of a release script whose `--help` exits non-zero: a usage comment
/// that wraps, an option loop over `case "$1"`, and code lines that pass
/// options to other programs.
const RELEASE_SCRIPT: &str = r#"#!/usr/bin/env bash
# Tag, build, and publish a release.
#
# Usage: release.sh <version> [--repo owner/name] [--quiet-minutes N]
#                  [--title T --body B] [--notes DIR]
#                  [--skip-billing] [--dry-run]
#
# Gates:
#   - the tag does not exist yet
#     (stable only); --skip-billing ignores billing-blocked checks only
set -euo pipefail
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO=$2; shift 2 ;;
    --quiet-minutes) QUIET_MIN=$2; shift 2 ;;
    --title) TITLE=$2; shift 2 ;;
    --body) BODY=$2; shift 2 ;;
    --notes) NOTES=$2; shift 2 ;;
    --skip-billing) SKIP=1; shift ;;
    --dry-run) DRY=1; shift ;;
    [0-9]*) VERSION=$1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$REPO" in
  example/project) PUBLISHER=x ;;
esac
VIEW=$(gh release view "$VERSION" \
  --json state,isDraft,author)
RUNS=$(gh api x \
  --paginate --jq '.workflow_runs' | jq -s 'add // []')
"#;

#[test]
fn a_script_source_names_every_option_its_usage_and_case_arms_take() {
    let found = rows(RELEASE_SCRIPT, true);
    assert_eq!(
        found
            .iter()
            .map(|row| row.command_id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "--repo",
            "--quiet-minutes",
            "--title",
            "--body",
            "--notes",
            "--skip-billing",
            "--dry-run"
        ]
    );
    assert_eq!(usage_of(&found, "--repo"), "tool.sh --repo owner/name");
    assert_eq!(
        usage_of(&found, "--quiet-minutes"),
        "tool.sh --quiet-minutes N"
    );
    assert_eq!(usage_of(&found, "--dry-run"), "tool.sh --dry-run");
    assert!(found
        .iter()
        .all(|row| row.parent_id.is_none() && row.name == row.command_id));
}

#[test]
fn code_lines_that_pass_options_to_other_programs_are_not_variations() {
    let found = ids(RELEASE_SCRIPT, true);
    for foreign in ["--json", "--paginate", "--jq", "-s"] {
        assert!(
            !found.contains(&foreign.to_owned()),
            "{foreign} leaked from code"
        );
    }
}

#[test]
fn an_option_table_reads_aliases_values_and_descriptions() {
    let help = concat!(
        "Options:\n",
        "  -r, --repo NAME     Repository to merge in\n",
        "  -n NUM, --count NUM  How many\n",
        "  --force             Skip the checks\n",
        "  -h, --help          Show this help\n",
        "  --version           Print the version\n",
    );
    let found = rows(help, false);
    assert_eq!(
        found
            .iter()
            .map(|row| row.command_id.as_str())
            .collect::<Vec<_>>(),
        vec!["--repo", "-r", "--count", "-n", "--force"]
    );
    assert_eq!(found[0].description, "Repository to merge in");
    assert_eq!(found[0].usage, "tool.sh --repo NAME");
    assert_eq!(found[1].description, "Same as --repo.");
    assert_eq!(found[2].usage, "tool.sh --count NUM");
    assert_eq!(found[4].usage, "tool.sh --force");
}

#[test]
fn prose_that_starts_with_an_option_is_not_a_row() {
    let help = "-- this tool merges things\n--force is dangerous and rarely needed\n";
    assert!(ids(help, false).is_empty());
}

#[test]
fn a_usage_line_names_options_with_inline_and_bracketed_values() {
    let help = "usage: tool [--mode=fast] [--out <file>] [-v] [-q | --quiet]\n";
    let found = rows(help, false);
    assert_eq!(
        found
            .iter()
            .map(|row| row.command_id.as_str())
            .collect::<Vec<_>>(),
        vec!["--mode", "--out", "-v", "-q", "--quiet"]
    );
    assert_eq!(usage_of(&found, "--mode"), "tool.sh --mode fast");
    assert_eq!(usage_of(&found, "--out"), "tool.sh --out <file>");
    assert_eq!(usage_of(&found, "-v"), "tool.sh -v");
}

#[test]
fn a_heredoc_usage_text_is_read_like_a_comment() {
    let script = concat!(
        "usage() {\n",
        "  cat <<'EOF'\n",
        "Usage: deploy.sh [options]\n",
        "  --target ENV   Where to deploy\n",
        "  --dry-run      Print the plan\n",
        "EOF\n",
        "}\n",
        "  --notanoption x y\n",
    );
    assert_eq!(ids(script, true), vec!["--target", "--dry-run"]);
}

#[test]
fn a_case_on_the_first_argument_names_subcommands_before_options() {
    let script = concat!(
        "case \"${1:-}\" in\n",
        "  build|b) shift; build \"$@\" ;; # Build the site\n",
        "  deploy) shift; deploy ;;\n",
        "  help) usage ;;\n",
        "  --verbose) VERBOSE=1 ;;\n",
        "esac\n",
        "case \"$mode\" in\n",
        "  fast) run_fast ;;\n",
        "esac\n",
    );
    let found = rows(script, true);
    assert_eq!(
        found
            .iter()
            .map(|row| row.command_id.as_str())
            .collect::<Vec<_>>(),
        vec!["build", "b", "deploy", "--verbose"]
    );
    assert_eq!(found[0].description, "Build the site");
}

#[test]
fn argparse_click_and_commander_calls_name_their_options() {
    let script = concat!(
        "parser.add_argument(\"-r\", \"--repo\", help=\"Repository\")\n",
        "parser.add_argument(\"--force\", action=\"store_true\", help=\"Skip checks\")\n",
        "parser.add_argument(\n",
        "    \"--count\",\n",
        "    type=int,\n",
        "    metavar=\"N\",\n",
        ")\n",
        "parser.add_argument(\"target\", help=\"Where\")\n",
        "@click.option(\"--name\", \"-n\", default=\"x\", help=\"Who\")\n",
        "program.option(\"-d, --dry-run\", \"Print the plan\")\n",
        "program.option(\"-o, --out <file>\", \"Write here\")\n",
    );
    let found = rows(script, true);
    assert_eq!(
        found
            .iter()
            .map(|row| row.command_id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "--repo",
            "-r",
            "--force",
            "--count",
            "--name",
            "-n",
            "--dry-run",
            "-d",
            "--out",
            "-o"
        ]
    );
    assert_eq!(usage_of(&found, "--repo"), "tool.sh --repo VALUE");
    assert_eq!(usage_of(&found, "--force"), "tool.sh --force");
    assert_eq!(usage_of(&found, "--count"), "tool.sh --count N");
    assert_eq!(
        found
            .iter()
            .find(|row| row.command_id == "--name")
            .unwrap()
            .description,
        "Who"
    );
    assert_eq!(usage_of(&found, "--dry-run"), "tool.sh --dry-run");
    assert_eq!(usage_of(&found, "--out"), "tool.sh --out <file>");
    assert_eq!(
        found
            .iter()
            .find(|row| row.command_id == "--dry-run")
            .unwrap()
            .description,
        "Print the plan"
    );
}

#[test]
fn getopts_letters_and_compared_arguments_are_options() {
    let script = concat!(
        "while getopts \":rn:v\" opt; do :; done\n",
        "if [ \"$1\" = \"--force\" ]; then :; fi\n",
        "if \"--quiet\" in sys.argv: pass\n",
        "if (process.argv.includes('--watch')) {}\n",
    );
    let found = rows(script, true);
    assert_eq!(
        found
            .iter()
            .map(|row| row.command_id.as_str())
            .collect::<Vec<_>>(),
        vec!["-r", "-n", "-v", "--force", "--quiet", "--watch"]
    );
    assert_eq!(usage_of(&found, "-n"), "tool.sh -n VALUE");
}

#[test]
fn only_catalog_safe_option_spellings_are_kept() {
    assert!(is_option_name("--dry-run"));
    assert!(is_option_name("-x"));
    assert!(is_option_name("--2fa"));
    assert!(!is_option_name("-"));
    assert!(!is_option_name("--"));
    assert!(!is_option_name("-xy"));
    assert!(!is_option_name("---x"));
    assert!(!is_option_name("--a.b"));
    assert!(!is_option_name("--é"));
    assert!(!is_option_name(&format!("--{}", "a".repeat(41))));
    assert!(is_option_name(&format!("--{}", "a".repeat(40))));
}

#[test]
fn a_read_reports_at_most_its_option_limit() {
    let help: String = (0..100)
        .map(|n| format!("  --opt{n}  Option {n}\n"))
        .collect();
    assert_eq!(ids(&help, false).len(), MAX_OPTIONS);
}
