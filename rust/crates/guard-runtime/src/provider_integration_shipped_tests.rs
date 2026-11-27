use std::collections::BTreeSet;
use std::path::Path;

use guard_command::provider_integration_compile::ProviderIntegrationCompileError as E;

use super::*;

const EXAMPLE: &[u8] =
    include_bytes!("../../../../tests/fixtures/provider_integrations/exampleshield/manifest.json");

fn contributions() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contributions/provider-integrations")
}

fn with_id(id: &str, verified: bool) -> Vec<u8> {
    let mut manifest: serde_json::Value = serde_json::from_slice(EXAMPLE).unwrap();
    manifest["id"] = id.into();
    manifest["publisher"]["verified"] = verified.into();
    serde_json::to_vec(&manifest).unwrap()
}

#[test]
fn shipped_lists_every_contributed_manifest_and_nothing_else() {
    let on_disk: BTreeSet<String> = std::fs::read_dir(contributions())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".json"))
        .collect();
    let listed: BTreeSet<String> = SHIPPED.iter().map(|(name, _)| (*name).to_owned()).collect();
    assert_eq!(listed.len(), SHIPPED.len(), "a manifest is listed twice");
    assert_eq!(
        listed, on_disk,
        "SHIPPED must list every manifest in contributions/provider-integrations/"
    );
    for (name, bytes) in SHIPPED {
        let on_disk = std::fs::read(contributions().join(name)).unwrap();
        assert_eq!(
            *bytes,
            on_disk.as_slice(),
            "{name} is embedded from another file"
        );
    }
}

#[test]
fn the_shipped_set_compiles_and_is_served_whole() {
    let compiled = compile_shipped(SHIPPED, VERIFIED).expect("the shipped set must compile");
    assert_eq!(compiled.len(), SHIPPED.len());
    let served: Vec<&str> = shipped_providers().iter().map(|p| p.id.as_str()).collect();
    let expected: Vec<&str> = compiled.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(served, expected);
    for id in VERIFIED {
        assert!(expected.contains(id), "{id} is verified but not shipped");
    }
}

#[test]
fn a_contributed_manifest_compiles_with_its_source_digest() {
    let compiled = compile_shipped(&[("provider.exampleshield.json", EXAMPLE)], &[]).unwrap();
    assert_eq!(compiled.len(), 1);
    assert_eq!(compiled[0].id, "provider.exampleshield");
    assert_eq!(compiled[0].manifest_digest.len(), 64);
    assert!(!compiled[0].verified);
}

#[test]
fn a_set_that_does_not_compile_serves_nothing() {
    let twin = with_id("provider.exampleshield", false);
    assert_eq!(
        compile_shipped(&[("a.json", EXAMPLE), ("b.json", &twin)], &[]).unwrap_err(),
        E::ProviderIdDuplicate
    );
    let fixture = with_id("provider.fixture-shield", false);
    assert_eq!(
        compile_shipped(&[("a.json", EXAMPLE), ("b.json", &fixture)], &[]).unwrap_err(),
        E::FixtureIdContributed
    );
    let claimed = with_id("provider.exampleshield", true);
    assert_eq!(
        compile_shipped(&[("a.json", &claimed)], &[]).unwrap_err(),
        E::PublisherVerificationUnproven
    );
    let honoured = compile_shipped(&[("a.json", &claimed)], &["provider.exampleshield"]).unwrap();
    assert!(honoured[0].verified);
}
