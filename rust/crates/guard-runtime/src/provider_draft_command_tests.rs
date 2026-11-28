use serde_json::json;

use super::*;

const MANIFEST: &str =
    include_str!("../../../../tests/fixtures/provider_integrations/exampleshield/manifest.json");

fn request(manifest: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({ "manifest": manifest })).unwrap()
}

#[test]
fn the_fixture_manifest_drafts_recordings_the_kit_reads() {
    let reply = run_command(&request(MANIFEST));
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["provider_id"], "provider.exampleshield");
    let text = reply["recordingsText"].as_str().unwrap();
    let parsed =
        guard_provider_integrations::conformance_fixtures::parse_recordings(text.as_bytes())
            .expect("the drafted file parses");
    assert_eq!(reply["recordings"], parsed.len());
}

#[test]
fn bad_requests_and_manifests_are_refused_with_a_code() {
    assert_eq!(run_command(b"{}")["error"]["code"], "request_invalid");
    assert_eq!(
        run_command(&request("{}"))["error"]["code"],
        "provider_integration_json_invalid"
    );
    let large = "x".repeat(MAX_MANIFEST_BYTES + 1);
    assert_eq!(
        run_command(&request(&large))["error"]["code"],
        "manifest_too_large"
    );
}
