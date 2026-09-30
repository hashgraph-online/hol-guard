//! Python oracle vectors and state/deadline bounds for option parsing.

use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct OracleGroup {
    options: BTreeSet<String>,
    known: BTreeSet<String>,
    inverse: BTreeSet<(String, String)>,
    subcommands: Vec<String>,
    required: BTreeSet<String>,
    cases: Vec<OracleCase>,
}

#[derive(Deserialize)]
struct OracleCase {
    args: Vec<String>,
    present: BTreeSet<String>,
    effective: Vec<(String, String, Option<String>)>,
    advance: Vec<Option<usize>>,
    subcommand: bool,
    all_flags: bool,
}

// Generated directly from the Python reference at c4bd916; includes long
// assignment ordering, inverse pairs, consumed help/dry-run operands, short
// clusters, Unicode classifications, unknown arity, and the `--` boundary.
#[test]
fn matches_python_option_oracles() {
    let groups: Vec<OracleGroup> = serde_json::from_str(PYTHON_ORACLES).expect("valid oracle JSON");
    let mut count = 0;
    for group in groups {
        for case in group.cases {
            let actual = argument_semantics(&case.args, &group.options, &group.inverse);
            assert_eq!(actual.present_flags, case.present, "flags {:?}", case.args);
            assert_eq!(
                actual.effective_options, case.effective,
                "effective options {:?}",
                case.args
            );
            for (name, token, value) in &case.effective {
                assert_eq!(actual.option_token(name), Some(token.as_str()));
                assert_eq!(actual.option_value(name), value.as_deref());
            }
            assert_eq!(actual.option_token("--not-in-fixture"), None);
            assert_eq!(actual.option_value("--not-in-fixture"), None);
            let advances: Vec<_> = case
                .args
                .iter()
                .map(|argument| known_option_advance(argument, &group.options, &group.known))
                .collect();
            assert_eq!(advances, case.advance, "advance {:?}", case.args);
            assert_eq!(
                matches_subcommands_conservatively(
                    &case.args,
                    &group.subcommands,
                    &group.options,
                    &group.known
                ),
                case.subcommand,
                "subcommands {:?}",
                case.args
            );
            assert_eq!(
                flags_present_in_all_option_parses(
                    &case.args,
                    &group.required,
                    &group.options,
                    &group.known
                ),
                case.all_flags,
                "all parses {:?}",
                case.args
            );
            count += 1;
        }
    }
    assert_eq!(count, ORACLE_CASE_COUNT);
}

#[test]
fn state_exhaustion_keeps_destructive_matching_and_denies_safety_proof() {
    let arguments = vec![
        "--future=value".to_owned(),
        "delete".to_owned(),
        "-n".to_owned(),
    ];
    let subcommands = vec!["delete".to_owned()];
    let empty = BTreeSet::new();
    let known = BTreeSet::from(["-n".to_owned()]);
    assert_eq!(
        subcommand_parse_outcome(&arguments, &subcommands, &empty, &known, 1, None),
        ParseOutcome::Uncertain
    );
    assert_eq!(
        flag_parse_outcome(&arguments, "-n", &empty, &known, 1, None),
        ParseOutcome::Uncertain
    );
    assert_ne!(ParseOutcome::Uncertain, ParseOutcome::NoMatch);
    assert_ne!(ParseOutcome::Uncertain, ParseOutcome::Match);
    // Verify the production budget itself, not only the injected low limit.
    let mut deep = vec!["--future=value".to_owned(); MAX_OPTION_PARSE_STATES];
    deep.extend(subcommands.clone());
    deep.push("-n".to_owned());
    assert!(matches_subcommands_conservatively(
        &deep,
        &subcommands,
        &empty,
        &known
    ));
    assert!(!flags_present_in_all_option_parses(
        &deep, &known, &empty, &known
    ));
}

#[test]
fn absent_requirements_are_vacuously_true_and_unknown_arity_can_consume_help() {
    let empty = BTreeSet::new();
    let known = BTreeSet::from(["--help".to_owned()]);
    assert!(flags_present_in_all_option_parses(
        &[],
        &empty,
        &empty,
        &empty
    ));
    let arguments = vec!["--future".to_owned(), "--help".to_owned()];
    assert!(!flags_present_in_all_option_parses(
        &arguments, &known, &empty, &known
    ));
    let arguments = vec!["--future=value".to_owned(), "--help".to_owned()];
    assert!(flags_present_in_all_option_parses(
        &arguments, &known, &empty, &known
    ));
}

#[test]
fn expired_outer_deadline_preserves_uncertainty_direction() {
    let empty = BTreeSet::new();
    let known = BTreeSet::from(["--help".to_owned()]);
    let arguments = vec!["delete".to_owned(), "--help".to_owned()];
    let subcommands = vec!["delete".to_owned()];
    let deadline = Some(Instant::now());
    assert!(matches_subcommands_conservatively_with_deadline(
        &arguments,
        &subcommands,
        &empty,
        &known,
        deadline
    ));
    assert!(!flags_present_in_all_option_parses_with_deadline(
        &arguments, &known, &empty, &known, deadline
    ));
}

const ORACLE_CASE_COUNT: usize = 187;
const PYTHON_ORACLES: &str = include_str!("../tests/fixtures/command-option-parsing-v1.json");
