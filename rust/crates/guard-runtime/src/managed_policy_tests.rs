use super::*;

use serde_json::json;

fn document(extra: Value) -> Value {
    let mut root = json!({"schemaVersion": POLICY_SCHEMA_VERSION});
    let Value::Object(fields) = extra else {
        unreachable!("test documents extend an object");
    };
    for (key, value) in fields {
        root[key] = value;
    }
    root
}

fn parse(extra: Value) -> ManagedPolicy {
    parse_managed_policy(&document(extra)).expect("document parses")
}

fn refuse(extra: Value) -> String {
    parse_managed_policy(&document(extra)).expect_err("document is refused")
}

#[test]
fn bare_document_takes_the_unmanaged_defaults() {
    let policy = parse(json!({}));
    assert_eq!(policy.schema_version, POLICY_SCHEMA_VERSION);
    assert!(policy.settings.is_empty());
    assert!(policy.locked_settings.is_empty());
    assert!(policy.required_harnesses.is_empty());
    assert_eq!(policy.network, ManagedNetworkPolicy::unmanaged_default());
    assert_eq!(policy.update, ManagedUpdatePolicy::default());
    assert_eq!(policy.integrity_trust, ManagedIntegrityTrust::default());
    assert_eq!(policy.daemon_startup, DaemonStartup::OnDemand);
    assert_eq!(policy.install_owner(), InstallOwner::User);
    assert!(policy.policy_bundle_keyring.is_none());
}

#[test]
fn schema_and_unknown_keys_refuse_the_whole_document() {
    assert_eq!(
        parse_managed_policy(&json!([])).unwrap_err(),
        "policy must be an object"
    );
    assert_eq!(
        parse_managed_policy(&json!({"schemaVersion": "hol-guard-mdm-policy.v2"})).unwrap_err(),
        "unsupported managed policy schema"
    );
    assert_eq!(
        refuse(json!({"zzz": 1, "aaa": 2})),
        "unknown policy keys: aaa, zzz"
    );
    assert_eq!(
        refuse(json!({"network": {"proxyFlavour": "socks"}})),
        "unknown network keys: proxyFlavour"
    );
}

#[test]
fn content_hash_is_the_canonical_document_digest() {
    let spaced = parse(json!({"requiredHarnesses": ["codex", "claude"]}));
    let other_order = parse_managed_policy(&json!({
        "requiredHarnesses": ["codex", "claude"],
        "schemaVersion": POLICY_SCHEMA_VERSION,
    }))
    .expect("document parses");
    // Key order in the installed file does not change the hash, but the
    // values do, so a tampered document hashes differently.
    assert_eq!(spaced.content_hash, other_order.content_hash);
    assert_ne!(
        spaced.content_hash,
        parse(json!({"requiredHarnesses": ["codex"]})).content_hash
    );
    assert_eq!(spaced.content_hash.len(), 64);
}

#[test]
fn locked_settings_must_resolve_to_a_managed_value() {
    let policy = parse(json!({
        "settings": {"approvals": {"mode": "ask"}},
        "lockedSettings": ["approvals.mode"],
    }));
    assert_eq!(
        policy.locked_settings,
        BTreeSet::from(["approvals.mode".to_owned()])
    );
    assert_eq!(
        refuse(json!({"settings": {}, "lockedSettings": ["approvals.mode"]})),
        "locked setting has no managed value: approvals.mode"
    );
    assert_eq!(
        refuse(json!({
            "settings": {"approvals": "ask"},
            "lockedSettings": ["approvals.mode"],
        })),
        "locked setting has no managed value: approvals.mode"
    );
    assert_eq!(
        refuse(json!({"lockedSettings": ["", "ok"]})),
        "lockedSettings must be an array of setting paths"
    );
    // A locked value of `null` is still a managed value.
    assert!(parse_managed_policy(&document(json!({
        "settings": {"approvals": {"mode": null}},
        "lockedSettings": ["approvals.mode"],
    })))
    .is_ok());
}

#[test]
fn required_harnesses_are_sorted_and_deduplicated() {
    let policy = parse(json!({"requiredHarnesses": ["codex", "claude", "codex"]}));
    assert_eq!(policy.required_harnesses, vec!["claude", "codex"]);
    assert_eq!(
        refuse(json!({"requiredHarnesses": ["codex", 1]})),
        "requiredHarnesses must be an array of names"
    );
}

#[test]
fn an_explicit_null_is_not_an_absent_key() {
    // Python substitutes its default only for a missing key; an installed
    // document that spells the field out as null is malformed.
    assert_eq!(
        refuse(json!({"daemonStartup": null})),
        "daemonStartup is invalid"
    );
    assert_eq!(
        refuse(json!({"lockedSettings": null})),
        "lockedSettings must be an array of setting paths"
    );
    assert_eq!(
        refuse(json!({"requiredHarnesses": null})),
        "requiredHarnesses must be an array of names"
    );
    assert_eq!(
        refuse(json!({"update": {"owner": null}})),
        "update.owner is invalid"
    );
    assert_eq!(
        refuse(json!({"update": {"channel": null}})),
        "update.channel must be a non-empty string"
    );
    assert_eq!(
        refuse(json!({"update": {"allowDowngrade": null}})),
        "update.allowDowngrade must be boolean"
    );
    assert_eq!(
        refuse(json!({"network": {"proxyMode": null}})),
        "network.proxyMode is invalid"
    );
    assert_eq!(
        refuse(json!({"network": {"allowPublicRegistries": null}})),
        "network.allowPublicRegistries must be boolean"
    );
    assert_eq!(
        refuse(json!({"settings": null})),
        "settings must be an object"
    );
    assert_eq!(
        refuse(json!({"network": null})),
        "network must be an object"
    );
    // The optional strings take null as "not configured".
    assert!(parse_managed_policy(&document(json!({
        "network": {"caBundlePath": null},
        "update": {"minimumVersion": null, "indexUrl": null},
    })))
    .is_ok());
}

#[test]
fn explicit_proxy_mode_and_its_url_travel_together() {
    let policy = parse(json!({
        "network": {"proxyMode": "explicit", "proxyUrl": "https://proxy.example:8443"},
    }));
    assert_eq!(policy.network.proxy_mode, ProxyMode::Explicit);
    assert_eq!(
        policy.network.proxy_url.as_deref(),
        Some("https://proxy.example:8443")
    );
    assert_eq!(
        refuse(json!({"network": {"proxyMode": "explicit"}})),
        "network.proxyUrl is required for explicit proxy mode"
    );
    assert_eq!(
        refuse(json!({"network": {"proxyUrl": "https://proxy.example"}})),
        "network.proxyUrl is only valid for explicit proxy mode"
    );
    assert_eq!(
        refuse(json!({"network": {"proxyMode": "sometimes"}})),
        "network.proxyMode is invalid"
    );
}

#[test]
fn a_proxy_url_is_an_https_origin_without_credentials() {
    let bad = |url: &str| refuse(json!({"network": {"proxyMode": "explicit", "proxyUrl": url}}));
    assert_eq!(
        bad("http://proxy.example"),
        "network.proxyUrl must be an absolute HTTPS URL"
    );
    assert_eq!(
        bad("proxy.example:8443"),
        "network.proxyUrl must be an absolute HTTPS URL"
    );
    assert_eq!(
        bad("https://:8443"),
        "network.proxyUrl must be an absolute HTTPS URL"
    );
    assert_eq!(
        bad("https://proxy.example:84a3"),
        "network.proxyUrl must be an absolute HTTPS URL"
    );
    assert_eq!(
        bad("https://proxy.example:99999"),
        "network.proxyUrl must be an absolute HTTPS URL"
    );
    assert_eq!(
        bad("https://proxy.example :8443"),
        "network.proxyUrl must be an absolute HTTPS URL"
    );
    assert_eq!(
        bad("https://operator:secret@proxy.example"),
        "network proxy credentials are forbidden in managed policy"
    );
    assert_eq!(
        bad("https://@proxy.example"),
        "network proxy credentials are forbidden in managed policy"
    );
    assert_eq!(
        bad("https://proxy.example/?retry=1"),
        "network.proxyUrl must not contain a query or fragment"
    );
    assert_eq!(
        bad("https://proxy.example/egress"),
        "network.proxyUrl must be an absolute HTTPS proxy origin"
    );
    assert_eq!(
        bad("https://proxy.example:"),
        "network.proxyUrl must be an absolute HTTPS proxy origin"
    );
    assert_eq!(
        bad("https://proxy.example:0"),
        "network.proxyUrl must be an absolute HTTPS proxy origin"
    );
    // A bracketed IPv6 authority with a port is a proxy origin; an unclosed
    // one is not a URL at all. The text inside the brackets has to be an
    // address urlsplit would accept, not merely a balanced pair.
    assert!(parse_managed_policy(&document(json!({
        "network": {"proxyMode": "explicit", "proxyUrl": "https://[2001:db8::1]:8443/"},
    })))
    .is_ok());
    assert!(parse_managed_policy(&document(json!({
        "network": {"proxyMode": "explicit", "proxyUrl": "https://[v1.future]/"},
    })))
    .is_ok());
    assert!(parse_managed_policy(&document(json!({
        "network": {"proxyMode": "explicit", "proxyUrl": "https://[::1%eth0]/"},
    })))
    .is_ok());
    assert_eq!(
        bad("https://[2001:db8::1:8443"),
        "network.proxyUrl must be an absolute HTTPS URL"
    );
    assert_eq!(
        bad("https://[not-an-ip]/"),
        "network.proxyUrl must be an absolute HTTPS URL"
    );
    assert_eq!(
        bad("https://[192.0.2.1]/"),
        "network.proxyUrl must be an absolute HTTPS URL"
    );
    assert_eq!(
        bad("https://[::1]extra/"),
        "network.proxyUrl must be an absolute HTTPS URL"
    );
}

#[test]
fn a_managed_ca_bundle_is_an_absolute_path() {
    let bundle = if cfg!(windows) {
        r"C:\ProgramData\HOL\roots.pem"
    } else {
        "/etc/hol/roots.pem"
    };
    let policy = parse(json!({"network": {"caBundlePath": bundle}}));
    assert_eq!(policy.network.ca_bundle_path, Some(PathBuf::from(bundle)));
    assert!(policy.network.trust_roots_path.is_none());
    assert_eq!(
        refuse(json!({"network": {"caBundlePath": "roots.pem"}})),
        "network.caBundlePath must be absolute"
    );
    assert_eq!(
        refuse(json!({"network": {"caBundlePath": "   "}})),
        "network.caBundlePath must be a non-empty string or null"
    );
    assert!(
        !parse(json!({"network": {"allowPublicRegistries": false}}))
            .network
            .allow_public_registries
    );
}

#[test]
fn update_policy_reads_owner_channel_and_index() {
    let policy = parse(json!({
        "update": {
            "owner": "mdm",
            "channel": "beta",
            "minimumVersion": "3.40.0",
            "allowDowngrade": true,
            "indexUrl": "https://packages.example/simple",
        },
    }));
    assert_eq!(policy.install_owner(), InstallOwner::Mdm);
    assert_eq!(policy.update.owner.as_str(), "mdm");
    assert_eq!(policy.update.channel, "beta");
    assert_eq!(policy.update.minimum_version.as_deref(), Some("3.40.0"));
    assert!(policy.update.allow_downgrade);
    assert_eq!(
        policy.update.index_url.as_deref(),
        Some("https://packages.example/simple")
    );
    assert_eq!(
        refuse(json!({"update": {"owner": "fleet"}})),
        "update.owner is invalid"
    );
    assert_eq!(
        refuse(json!({"update": {"channel": ""}})),
        "update.channel must be a non-empty string"
    );
    assert_eq!(
        refuse(json!({"update": {"indexUrl": "http://packages.example"}})),
        "update.indexUrl must be an absolute HTTPS URL"
    );
    assert_eq!(
        refuse(json!({"update": {"indexUrl": "https://user@packages.example"}})),
        "update.indexUrl credentials are forbidden in managed policy"
    );
    // Unlike a proxy URL, an index URL keeps its path.
    assert_eq!(
        parse(json!({"update": {"indexUrl": "https://packages.example/a/b"}}))
            .update
            .index_url
            .as_deref(),
        Some("https://packages.example/a/b")
    );
}

#[test]
fn daemon_startup_is_one_of_two_spellings() {
    assert_eq!(
        parse(json!({"daemonStartup": "login"})).daemon_startup,
        DaemonStartup::Login
    );
    assert_eq!(DaemonStartup::Login.as_str(), "login");
    assert_eq!(DaemonStartup::OnDemand.as_str(), "on-demand");
    assert_eq!(
        refuse(json!({"daemonStartup": "boot"})),
        "daemonStartup is invalid"
    );
}

#[test]
fn integrity_trust_pins_release_keys_and_signers() {
    let key = PYTHON_BASE64.encode([7u8; RELEASE_KEY_BYTES]);
    let policy = parse(json!({
        "integrityTrust": {
            "releasePublicKeys": {"2026-release": key.clone()},
            "macosTeamId": "ABCDE12345",
            "windowsSignerThumbprints": [
                "aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd",
                "AABBCCDDEEFF00112233445566778899AABBCCDD",
            ],
        },
    }));
    assert_eq!(
        policy
            .integrity_trust
            .release_public_keys
            .get("2026-release"),
        Some(&vec![7u8; RELEASE_KEY_BYTES])
    );
    assert_eq!(
        policy.integrity_trust.macos_team_id.as_deref(),
        Some("ABCDE12345")
    );
    // Spacing and case are normalised, so the two spellings pin one signer.
    assert_eq!(
        policy.integrity_trust.windows_signer_thumbprints,
        vec!["AABBCCDDEEFF00112233445566778899AABBCCDD".to_owned()]
    );
    assert_eq!(
        refuse(json!({"integrityTrust": {"releasePublicKeys": {"id": "not base64!"}}})),
        "release public key is not valid base64"
    );
    assert_eq!(
        refuse(json!({"integrityTrust": {"releasePublicKeys": {"": key}}})),
        "release public keys must map non-empty ids to base64 strings"
    );
    assert_eq!(
        refuse(json!({"integrityTrust": {"releasePublicKeys": {"id": 7}}})),
        "release public keys must map non-empty ids to base64 strings"
    );
    assert_eq!(
        refuse(json!({
            "integrityTrust": {"releasePublicKeys": {"id": PYTHON_BASE64.encode([1u8; 16])}},
        })),
        "release public keys must be 32-byte Ed25519 keys"
    );
    assert_eq!(
        refuse(json!({"integrityTrust": {"windowsSignerThumbprints": ["AABB"]}})),
        "Windows signer thumbprints must be SHA-1 certificate thumbprints"
    );
    assert_eq!(
        refuse(json!({"integrityTrust": {"windowsSignerThumbprints": [""]}})),
        "integrityTrust.windowsSignerThumbprints must be an array of strings"
    );
    assert_eq!(
        refuse(json!({"integrityTrust": {"teamId": "ABCDE12345"}})),
        "unknown integrityTrust keys: teamId"
    );
}

#[test]
fn base64_matches_python_validate_true() {
    // CPython's `validate=True` rejects stray characters and non-canonical
    // padding but tolerates a final character with non-zero unused bits.
    assert!(PYTHON_BASE64.decode("QUJD").is_ok());
    assert!(PYTHON_BASE64.decode("QUJ=").is_ok());
    assert!(PYTHON_BASE64.decode("QUJD\n").is_err());
    assert!(PYTHON_BASE64.decode("QUJ").is_err());
}

#[test]
fn a_policy_bundle_keyring_is_rebuilt_as_the_canonical_payload() {
    let policy = parse(json!({
        "policyBundleKeyring": {
            "contractVersion": crate::policy_bundle_keys::KEYRING_CONTRACT_VERSION,
            "purpose": crate::policy_bundle_keys::KEY_PURPOSE,
            "workspaceId": "workspace-1",
            "keys": [],
        },
    }));
    assert_eq!(
        policy.policy_bundle_keyring,
        Some(json!({
            "contractVersion": crate::policy_bundle_keys::KEYRING_CONTRACT_VERSION,
            "purpose": crate::policy_bundle_keys::KEY_PURPOSE,
            "workspaceId": "workspace-1",
            "keys": [],
        }))
    );
    assert_eq!(
        refuse(json!({"policyBundleKeyring": {"keys": []}})),
        "policyBundleKeyring is invalid"
    );
    // The keyring contract takes the workspace id as stored, so padding is
    // refused rather than trimmed: a trimmed id would verify bundles under a
    // workspace the document does not name.
    for workspace_id in [json!(" workspace-1 "), json!("   "), json!(1)] {
        assert_eq!(
            refuse(json!({
                "policyBundleKeyring": {
                    "contractVersion": crate::policy_bundle_keys::KEYRING_CONTRACT_VERSION,
                    "purpose": crate::policy_bundle_keys::KEY_PURPOSE,
                    "workspaceId": workspace_id,
                    "keys": [],
                },
            })),
            "policyBundleKeyring is invalid"
        );
    }
}

#[test]
fn settings_are_kept_verbatim_for_the_native_config_load() {
    let policy = parse(json!({
        "settings": {"approvals": {"mode": "ask", "retries": 2}, "telemetry": false},
    }));
    assert_eq!(
        setting_at_path(&policy.settings, "approvals.retries"),
        Some(&json!(2))
    );
    assert_eq!(setting_at_path(&policy.settings, "approvals.missing"), None);
    assert_eq!(setting_at_path(&policy.settings, "telemetry.mode"), None);
    assert_eq!(
        refuse(json!({"settings": []})),
        "settings must be an object"
    );
}
