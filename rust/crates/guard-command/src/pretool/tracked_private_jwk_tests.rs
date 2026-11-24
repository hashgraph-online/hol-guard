//! A JSON Web Key keeps its private parts in one-letter members the
//! credential scan does not read, so a committed document that holds one is
//! never clean, in any format and under any name.
use super::super::{Tracked, TrackedFiles};
use super::tests::{fixture, write_index};
use super::*;

const D: &str = "Wk3hQ8pX2mN7vR4tY9bL1cF6gJ0sD5aE8uI3oP2qZ7x";

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

#[test]
fn a_private_jwk_is_read_in_every_document_format() {
    let json = format!("{{\"kty\": \"EC\", \"crv\": \"P-256\", \"d\": \"{D}\"}}");
    let yaml = format!("kty: EC\ncrv: P-256\nd: {D}\n");
    let toml = format!("[signing]\nkty = \"RSA\"\np = \"{D}\"\n");
    let markdown =
        format!("# Signing key\n\n```json\n{{\n  \"kty\": \"oct\",\n  \"k\": \"{D}\"\n}}\n```\n");
    let escaped = format!("{{\"kty\": \"EC\", \"\\u0064\": \"{D}\"}}");
    for text in [json, yaml, toml, markdown, escaped] {
        assert!(private_jwk(&text), "{text}");
    }
}

#[test]
fn a_public_jwk_or_prose_about_keys_is_not_a_private_jwk() {
    let public = "{\"kty\": \"EC\", \"crv\": \"P-256\", \"x\": \"Wk3hQ8pX2mN7vR4tY9bL1cF6gJ0sD5aE8uI3oP2qZ7x\", \"y\": \"Wk3hQ8pX2mN7vR4tY9bL1cF6gJ0sD5aE8uI3oP2qZ7x\"}";
    let placeholder = "kty: EC\nd: <private scalar>\n";
    let no_kty = format!("id: {D}\nd: {D}\n");
    let prose =
        "# Wallet keys\n\nRotate the key with `kty` set and the d member kept in the vault.\n";
    let word = format!("kty: EC\nbuild: {D}\nupload_id: {D}\n");
    for text in [
        public.to_owned(),
        placeholder.to_owned(),
        no_kty,
        prose.to_owned(),
        word,
    ] {
        assert!(!private_jwk(&text), "{text}");
    }
}

/// A key-named YAML or Markdown document passes the name proof, so the
/// committed-content proof is what has to hold a JWK it carries.
#[test]
fn a_committed_document_holding_a_private_jwk_is_never_clean() {
    let (_home, project) = fixture();
    let notes = "docs/keys/wallet-key.md";
    let yaml = "config/keys/wallet-key.yaml";
    write(
        &project.join(notes),
        "# Wallet key\n\nRotate it every quarter.\n",
    );
    write(
        &project.join(yaml),
        &format!("kty: EC\ncrv: P-256\nd: {D}\n"),
    );
    write_index(&project.join(".git"), &[notes, yaml]);
    assert!(TrackedFiles::default().non_secret(&project.join(notes)));
    assert_eq!(
        TrackedFiles::default().classify(&project.join(yaml)),
        Tracked::SecretManifest
    );
}
