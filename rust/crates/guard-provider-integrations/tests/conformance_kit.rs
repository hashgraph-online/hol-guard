//! Runs the provider conformance kit (PRD 6.12) over the reference fixture provider and every
//! manifest under `contributions/provider-integrations/`, with the recordings under
//! `tests/fixtures/provider_integrations/<slug>/` and the browser rows of the benign gate.

use std::fs;
use std::path::{Path, PathBuf};

use guard_provider_integrations::conformance::run_conformance;
use guard_provider_integrations::conformance_fixtures::{browser_corpus, parse_recordings};
use guard_provider_integrations::noise::BaselineDecision;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn corpus() -> Vec<BaselineDecision> {
    let gate = fs::read(repo().join("tests/fixtures/benign_false_positive_gate.json")).unwrap();
    let corpus = browser_corpus(&gate).expect("the benign gate has an unknown browser row");
    assert!(!corpus.is_empty(), "the benign gate has no browser rows");
    corpus
}

fn slug(manifest: &[u8]) -> String {
    let value: serde_json::Value = serde_json::from_slice(manifest).expect("manifest is not JSON");
    let id = value["id"].as_str().expect("manifest has no id");
    id.strip_prefix("provider.")
        .expect("manifest id does not start with provider.")
        .to_owned()
}

fn check(manifest: &[u8], label: &str) {
    let fixtures = repo()
        .join("tests/fixtures/provider_integrations")
        .join(slug(manifest))
        .join("recordings.json");
    let bytes = fs::read(&fixtures)
        .unwrap_or_else(|_| panic!("{label}: add recorded responses at {}", fixtures.display()));
    let recordings =
        parse_recordings(&bytes).unwrap_or_else(|error| panic!("{label}: {}", error.code()));
    let borrowed: Vec<_> = recordings
        .iter()
        .map(|recording| recording.borrow())
        .collect();
    let report = run_conformance(manifest, &borrowed, &corpus());
    let failed: Vec<String> = report
        .checks
        .iter()
        .flat_map(|check| {
            check
                .problems
                .iter()
                .map(move |problem| format!("{}: {problem}", check.id))
        })
        .collect();
    assert!(
        failed.is_empty(),
        "{label} failed conformance:\n{}",
        failed.join("\n")
    );
}

#[test]
fn the_reference_fixture_provider_passes() {
    let manifest =
        fs::read(repo().join("tests/fixtures/provider_integrations/exampleshield/manifest.json"))
            .unwrap();
    check(&manifest, "exampleshield");
}

#[test]
fn every_contributed_provider_passes() {
    let directory = repo().join("contributions/provider-integrations");
    let mut manifests: Vec<PathBuf> = fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    manifests.sort();
    for path in manifests {
        let label = path.file_name().unwrap().to_string_lossy().into_owned();
        check(&fs::read(&path).unwrap(), &label);
    }
}
