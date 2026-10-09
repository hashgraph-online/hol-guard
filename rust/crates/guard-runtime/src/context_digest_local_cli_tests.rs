//! Vectors were produced by the Python derivation these identities replace,
//! so stored grants keep matching after the move.

use super::{local_cli_identity, slug, SLUG_MAX_PARTS};
use guard_contracts::{LocalCliIdentitySourceV1, LocalCliIdentityV1};
use serde_json::json;

const CONTENT: &str = "abababababababababababababababababababababababababababababababab";

fn identity(source: LocalCliIdentitySourceV1) -> Option<LocalCliIdentityV1> {
    local_cli_identity(&source).unwrap()
}

fn expected(cli_id: &str, name: &str, kind: &str, identity_hash: &str) -> LocalCliIdentityV1 {
    LocalCliIdentityV1 {
        cli_id: cli_id.to_owned(),
        name: name.to_owned(),
        kind: kind.to_owned(),
        identity_hash: identity_hash.to_owned(),
    }
}

#[test]
fn script_identity_matches_stored_grants() {
    let found = identity(LocalCliIdentitySourceV1::Script {
        entrypoint: json!({
            "kind": "python-script",
            "status": "verified",
            "sha256": CONTENT,
            "path": "  /opt/tools/\u{dc}ber Tool.v2-script.PY  ",
        }),
    });
    assert_eq!(
        found,
        Some(expected(
            "local-cli.ber-tool-v2-script-py-88f7026e",
            "\u{dc}ber Tool.v2-script.PY",
            "script",
            "e5219691198dd8a4060094e0d446b11985fbcac9192e3af4abfb284bd3995baf",
        ))
    );
}

#[test]
fn script_identity_requires_verified_file_scripts() {
    for (kind, status) in [
        ("python-script", "unverified"),
        ("bun-package-script", "verified"),
        ("inline-script", "verified"),
        ("python-c", "verified"),
        ("python-module", "verified"),
    ] {
        let entrypoint =
            json!({"kind": kind, "status": status, "sha256": CONTENT, "path": "/a.py"});
        assert_eq!(
            identity(LocalCliIdentitySourceV1::Script { entrypoint }),
            None
        );
    }
    let short_hash =
        json!({"kind": "direct-script", "status": "verified", "sha256": "ab", "path": "/a"});
    assert_eq!(
        identity(LocalCliIdentitySourceV1::Script {
            entrypoint: short_hash
        }),
        None
    );
    let blank_path = json!({"kind": "direct-script", "status": "verified", "sha256": CONTENT, "path": " \u{1f} "});
    assert_eq!(
        identity(LocalCliIdentitySourceV1::Script {
            entrypoint: blank_path
        }),
        None
    );
}

#[test]
fn executable_identity_matches_stored_grants() {
    let name = "My.CLI__Tool--with-many-parts-a-b-c-d-e-f-g-h";
    let found = identity(LocalCliIdentitySourceV1::Executable {
        executable: json!({"status": "verified", "sha256": CONTENT, "path": "/usr/local/bin/my-cli"}),
        name: name.to_owned(),
    });
    assert_eq!(
        found,
        Some(expected(
            "local-cli.my-cli-tool-with-many-parts-a-b-3c66838e",
            name,
            "executable",
            "53edb218496586d2167de5565d2c8e1c22c4d3a2d4e082cb90237d198e91cd9c",
        ))
    );
    let uppercase = CONTENT.to_uppercase();
    let rejected = identity(LocalCliIdentitySourceV1::Executable {
        executable: json!({"status": "verified", "sha256": uppercase, "path": "/usr/local/bin/my-cli"}),
        name: name.to_owned(),
    });
    assert_eq!(rejected, None);
}

#[test]
fn runner_identities_match_stored_grants() {
    let local_bin = |version: Option<&str>| {
        let mut bin = json!({
            "resolved_path": "/w/node_modules/.bin/eslint",
            "content_hash": format!("sha256:{CONTENT}"),
        });
        if let Some(version) = version {
            bin["installed_version"] = json!(version);
        }
        LocalCliIdentitySourceV1::RunnerLocalBin {
            name: "eslint".to_owned(),
            package_name: "eslint".to_owned(),
            local_bin: bin,
        }
    };
    assert_eq!(
        identity(local_bin(Some("9.1.0"))),
        Some(expected(
            "local-cli.eslint-144fb167",
            "eslint",
            "executable",
            "1fe2e43491b55ef10ac3bb3b8446a48cd4bf6714b2beaa7da04ef2b091b2c565",
        ))
    );
    assert_eq!(
        identity(local_bin(None)).unwrap().identity_hash,
        "f05b3d22b1483321ba8c2373fa1aa1856c18ab53699d2f7a4d53ec56f15f6068"
    );
    let name = "create-app-a-b-c-d-e-f-g";
    assert_eq!(
        identity(LocalCliIdentitySourceV1::RegistryPackage {
            name: name.to_owned(),
            package_name: "@scope/cr\u{e9}ate-app".to_owned(),
        }),
        Some(expected(
            "local-cli.npm-create-app-a-b-c-d-e-59ae2bd7",
            name,
            "executable",
            "07564c0e4f10d7a79824f452082b8dd5d1821b18eb9a9669fa0170cd7f28b37e",
        ))
    );
}

#[test]
fn package_json_identity_matches_stored_grants() {
    let package_name = "Scope-My_App.\u{dc}n\u{ef}code-very-long-name-here";
    assert_eq!(
        identity(LocalCliIdentitySourceV1::PackageJson {
            manifest_path: "/w/app/package.json".to_owned(),
            content_sha256: CONTENT.to_owned(),
            package_name: package_name.to_owned(),
        }),
        Some(expected(
            "local-cli.pkg-scopemyappncodev-5f45bec5",
            package_name,
            "script",
            "d9d206cd5087858c1c92ba252deca501babfff241ddc4841bebd210920651d0b",
        ))
    );
}

#[test]
fn slug_matches_python_rules() {
    for (value, slugged) in [
        ("", "cli"),
        ("---", "cli"),
        ("\u{130}stanbul", "i-stanbul"),
        ("\u{212a}elvin", "kelvin"),
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-b",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        ("x.y.z", "x-y-z"),
    ] {
        assert_eq!(slug(value, SLUG_MAX_PARTS), slugged, "{value:?}");
    }
}
