use super::*;

// Digests the Python runtime snapshot computed for these views before the
// resident took it over; policy versions and saved bindings carry them.
const PROTECTED_DIGEST: &str = "b174519abd9d7b38cd53d4d3a856e60357db724e45a08423a7d1b81a127055bb";
const UNENROLLED_DIGEST: &str = "fdcbc6e8a20c1ae5f7de8d097c758084f14d96e022c60db0565fb3f2a70e94b1";

fn catalog() -> String {
    "ab".repeat(32)
}

fn snapshot_layer(
    kind: &str,
    lockdown: bool,
    controls: Vec<NativeExtensionControlV1>,
) -> NativeExtensionControlLayerV1 {
    NativeExtensionControlLayerV1 {
        catalog_digest: catalog(),
        ..layer(kind, lockdown, controls)
    }
}

fn protected_layers() -> Vec<NativeExtensionControlLayerV1> {
    vec![
        snapshot_layer(
            "local-admin",
            false,
            vec![enabled_permission(ALPHA_WRITE), disabled_extension(ALPHA)],
        ),
        snapshot_layer("signed-cloud", true, Vec::new()),
    ]
}

fn snapshot_request(
    health: &str,
    revision: u64,
    managed_revision: u64,
    layers: Vec<NativeExtensionControlLayerV1>,
) -> ExtensionControlRequestV1 {
    request(ExtensionControlQueryV1::SnapshotDigest {
        catalog_digest: catalog(),
        health: health.to_owned(),
        revision,
        managed_revision,
        layers,
    })
}

fn snapshot_digest(request: &ExtensionControlRequestV1) -> String {
    let result = run(request);
    assert_eq!(result.status, "ok", "{}", result.code);
    match result.payload {
        Some(ExtensionControlPayloadV1::SnapshotDigest { digest }) => digest,
        other => panic!("expected snapshot digest payload, got {other:?}"),
    }
}

#[test]
fn snapshot_digest_matches_the_python_digest() {
    assert_eq!(
        snapshot_digest(&snapshot_request("protected", 3, 2, protected_layers())),
        PROTECTED_DIGEST
    );
    assert_eq!(
        snapshot_digest(&snapshot_request("unenrolled", 0, 0, Vec::new())),
        UNENROLLED_DIGEST
    );
}

#[test]
fn snapshot_digest_ignores_layer_and_control_order() {
    let mut layers = protected_layers();
    layers.reverse();
    layers[1].controls.reverse();
    assert_eq!(
        snapshot_digest(&snapshot_request("protected", 3, 2, layers)),
        PROTECTED_DIGEST
    );
}

#[test]
fn snapshot_digest_is_the_binding_effective_digest() {
    let binding = guard_contracts::NativeCommandControlBindingV1 {
        schema: guard_contracts::NATIVE_COMMAND_CONTROL_BINDING_SCHEMA.to_owned(),
        program_digest: catalog(),
        catalog_digest: catalog(),
        trust_digest: catalog(),
        health: "protected".to_owned(),
        revision: 3,
        managed_revision: 2,
        effective_digest: String::new(),
        layers: protected_layers(),
        authority: None,
        active_security_digest: None,
    };
    assert_eq!(
        binding.compute_effective_digest().unwrap(),
        PROTECTED_DIGEST
    );
}

#[test]
fn snapshot_digest_refuses_an_unknown_health_or_invalid_layer() {
    assert_eq!(
        error_code(&snapshot_request("healthy", 3, 2, protected_layers())),
        "native_extension_control_snapshot_invalid"
    );
    let mut invalid = protected_layers();
    invalid[0]
        .controls
        .push(disabled_extension("not-a-command"));
    assert_eq!(
        error_code(&snapshot_request("protected", 3, 2, invalid)),
        "native_extension_control_layer_invalid"
    );
    let mut non_ascii = snapshot_request("protected", 3, 2, protected_layers());
    if let ExtensionControlQueryV1::SnapshotDigest { catalog_digest, .. } = &mut non_ascii.query {
        catalog_digest.push('\u{e9}');
    }
    assert_eq!(
        error_code(&non_ascii),
        "native_extension_control_snapshot_invalid"
    );
}

#[test]
fn snapshot_digest_refuses_a_snapshot_the_resident_would_not_bind() {
    let mut other_catalog = protected_layers();
    other_catalog[1].catalog_digest = "cd".repeat(32);
    let mut duplicate_kind = protected_layers();
    duplicate_kind[1].kind = "local-admin".to_owned();
    let mut duplicate_target = protected_layers();
    duplicate_target[0].controls.push(disabled_extension(ALPHA));
    for layers in [other_catalog, duplicate_kind, duplicate_target] {
        assert_eq!(
            error_code(&snapshot_request("protected", 3, 2, layers)),
            "native_extension_control_snapshot_invalid"
        );
    }
    let mut short_catalog = snapshot_request("unenrolled", 0, 0, Vec::new());
    if let ExtensionControlQueryV1::SnapshotDigest { catalog_digest, .. } = &mut short_catalog.query
    {
        catalog_digest.truncate(10);
    }
    assert_eq!(
        error_code(&short_catalog),
        "native_extension_control_snapshot_invalid"
    );
}
