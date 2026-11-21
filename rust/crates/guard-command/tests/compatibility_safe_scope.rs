//! A safe declarative variant never proves an unrelated capability safe.

use guard_command::native_command_program::packaged_command_program;
use guard_command::{parse_command, CommandModelRequestV1};
use guard_contracts::NativeCommandObservationBatchV1;

fn observations(command: &str) -> NativeCommandObservationBatchV1 {
    let program = packaged_command_program().unwrap();
    let active = program
        .extensions
        .iter()
        .map(|extension| extension.extension_id.clone())
        .collect();
    let model = parse_command(&CommandModelRequestV1 {
        command: command.into(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "guard-shell".into(),
    })
    .unwrap();
    program.observe(&model, &active, None).unwrap()
}

#[test]
fn a_declarative_help_variant_and_the_capability_grammar_agree_about_help() {
    // The catalog neutralises its own rule through the `help` safe variant.
    // Until the grammar read the same flag, it still attributed
    // `command.github.workflow` to the same words, so printing the help of a
    // command that cancels a run raised a review card for cancelling one.
    let observed = observations("gh run cancel --help");
    let help = observed
        .observations
        .iter()
        .find(|item| item.rule_id == "command.cicd.github.run-administration")
        .unwrap();
    assert!(help.effective_segment_indexes.is_empty());
    assert!(!help.safe_variants.is_empty());
    assert!(!observed
        .observations
        .iter()
        .any(|item| item.rule_id == "command.github.workflow"));
}

#[test]
fn a_declarative_help_variant_never_erases_the_run_it_describes() {
    let observed = observations("gh run cancel 12345");
    let workflow = observed
        .observations
        .iter()
        .find(|item| item.rule_id == "command.github.workflow")
        .unwrap();
    assert_eq!(workflow.effective_segment_indexes, [0]);
    let administration = observed
        .observations
        .iter()
        .find(|item| item.rule_id == "command.cicd.github.run-administration")
        .unwrap();
    assert_eq!(administration.effective_segment_indexes, [0]);
}

#[test]
fn compatibility_preview_suppression_is_scoped_to_each_segment() {
    let observed =
        observations("git push origin main --force --dry-run && git push origin main --force");
    let push = observed
        .observations
        .iter()
        .find(|item| item.rule_id == "command.git.push")
        .unwrap();
    assert_eq!(push.effective_segment_indexes, [1]);
    assert_eq!(
        push.matcher_evidence
            .iter()
            .map(|item| item.segment_index)
            .collect::<Vec<_>>(),
        [1]
    );
    let forced = observed
        .observations
        .iter()
        .find(|item| item.rule_id == "command.git.force-push")
        .unwrap();
    assert_eq!(forced.effective_segment_indexes, [1]);
}
