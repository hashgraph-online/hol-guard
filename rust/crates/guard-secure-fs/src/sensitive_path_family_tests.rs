use super::{sensitive_path_family, sensitive_path_family_beside_name_proof};
use std::path::Path;

/// Wrangler keeps a worker's local secrets in `.dev.vars`, with one
/// `.dev.vars.<environment>` file per environment.
#[test]
fn wrangler_dev_vars_files_are_sensitive() {
    for path in [
        "workers/api/.dev.vars",
        ".dev.vars.staging",
        "workers\\api\\.DEV.VARS",
    ] {
        assert_eq!(
            sensitive_path_family(Path::new(path)),
            Some(("Wrangler local secrets file", "high")),
            "{path}"
        );
    }
    for path in [
        "workers/api/dev.vars",
        "workers/api/.dev.varsity",
        "src/vars.ts",
    ] {
        assert_eq!(sensitive_path_family(Path::new(path)), None, "{path}");
    }
}

#[test]
fn a_key_named_document_keeps_the_container_family_outside_the_name_proof() {
    // A project document that spells the marker out describes a feature:
    // `private_key_jwt` is an OpenID Connect client authentication method.
    // Only a screen that also runs `credential_named_path` and the
    // committed-document proof drops the container family for it; every other
    // screen, such as the post-tool source review and project context reads,
    // keeps refusing the name, so an untracked `wallet-key.json` stays held
    // wherever no proof runs.
    for path in [
        "docs/auth/private-key-jwt-client-auth.md",
        "docs/auth/PRIVATE-KEY-JWT.md",
        "contracts/wallet-key-rotation.json",
        "config/private_key_jwt.toml",
        "deploy/wallet-key-rotation.yaml",
        "deploy/wallet-key-rotation.yml",
        "keys/wallet-key.json",
    ] {
        assert_eq!(
            sensitive_path_family(Path::new(path)),
            Some(("wallet/private-key file", "critical")),
            "{path}"
        );
        assert_eq!(
            sensitive_path_family_beside_name_proof(Path::new(path)),
            None,
            "{path}"
        );
        assert!(crate::credential_named_path(Path::new(path)), "{path}");
    }
}

#[test]
fn key_containers_keep_the_container_family() {
    for path in [
        "secrets/prod-private-key-backup.tar.gz",
        "secrets/my-private-key.txt",
        "secrets/service-private-key",
        "secrets/private_key.ts",
        "secrets/.private-key.md",
        "secrets/wallet-key-export.sql",
        "secrets/private-key.pem",
    ] {
        for family in [
            sensitive_path_family,
            sensitive_path_family_beside_name_proof,
        ] {
            assert_eq!(
                family(Path::new(path)),
                Some(("wallet/private-key file", "critical")),
                "{path}"
            );
        }
    }
    // A key extension is read before either name rule.
    for path in ["secrets/wallet.key", "secrets/private.key", "tls/api.key"] {
        assert_eq!(
            sensitive_path_family(Path::new(path)),
            Some(("private-key file", "critical")),
            "{path}"
        );
    }
}
