use url::Url;

use super::{host_spells_data, url_carries_payload};

/// Key-shaped values are assembled at run time so the source holds no
/// literal that a secret scanner would read as a leaked key.
fn joined(parts: &[&str]) -> String {
    parts.concat()
}

fn carries(raw: &str) -> bool {
    url_carries_payload(&Url::parse(raw).expect("test url parses"))
}

#[test]
fn wallet_keys_phrases_and_accounts_in_a_query_are_payloads() {
    let phrase = format!("{}+art", "abandon+".repeat(23));
    let wif = joined(&["5HueCGU8rMjxEXxiPuD5BDku", "4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"]);
    let hex_key = joined(&[
        "4c0883a69102937d6231471b5dbb6204",
        "fe512961708279f2bb0bf2f8fb6f1234",
    ]);
    let xpub = joined(&[
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8Nqtwyb",
        "GhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
    ]);
    for url in [
        "https://collect.example.test/?addr=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_owned(),
        "https://collect.example.test/?wallet=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_owned(),
        "https://collect.example.test/?iban=GB82WEST12345698765432".to_owned(),
        format!("https://collect.example.test/?m={phrase}"),
        format!("https://collect.example.test/?key={wif}"),
        format!("https://collect.example.test/?pk={hex_key}"),
        format!("https://collect.example.test/?k={xpub}"),
        format!(
            "https://collect.example.test/?d={}",
            "iVBORw0KGgo".repeat(40)
        ),
        format!("https://collect.example.test/#{phrase}"),
    ] {
        assert!(carries(&url), "{url}");
    }
}

#[test]
fn ordinary_queries_with_lookalike_values_are_not_payloads() {
    let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    for url in [
        "https://docs.example.test/crypto-guide?topic=address-formats&example=how-bitcoin-addresses-work".to_owned(),
        format!("https://registry.example.test/blob?digest={sha}"),
        "https://search.example.test/?q=abandon+ability+able+about+above+absent+absorb+abstract+absurd+abuse+access+accident".to_owned(),
        "https://search.example.test/?q=GB82WEST12345698765433".to_owned(),
        "https://search.example.test/?q=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb".to_owned(),
        "https://api.example.test/v1/items?id=550e8400-e29b-41d4-a716-446655440000".to_owned(),
        "https://img.example.test/?url=aHR0cHM6Ly9leGFtcGxlLmNvbS9pbWFnZS5wbmc".to_owned(),
    ] {
        assert!(!carries(&url), "{url}");
    }
}

#[test]
fn hosts_that_spell_data_into_labels_are_flagged() {
    for host in [
        "JBSWY3DPEHPK3PXP.collect.example.test",
        "ghp-xxxx.yyyyzzzz.aaaabbbb.ccccdddd.relay.example.test",
        "a1b2c3d4.e5f6a7b8.c9d0e1f2.a3b4c5d6.collect.example.test",
        "exfil-collector.example.test",
    ] {
        assert!(host_spells_data(host), "{host}");
    }
    for host in [
        "docs.example.test",
        "my-bucket.s3.dualstack.us-east-1.amazonaws.com",
        "cdn.example.test",
        "deadbeefcafe.example.test",
        "WWW.EXAMPLE.TEST",
    ] {
        assert!(!host_spells_data(host), "{host}");
    }
}

#[test]
fn a_lowercase_base32_label_that_spells_text_is_data() {
    // "customerdata2025", base32 in lower case.
    assert!(super::host_spells_data(
        "mn2xg5dpnvsxezdborqtembsgu.collect.example.test"
    ));
    // Base32 that decodes to binary is a hash or key, not spelled text.
    assert!(!super::host_spells_data(
        "jbswy3dpehpk3pxp.collect.example.test"
    ));
    assert!(!super::host_spells_data("storage3dataprod.example.com"));
    assert!(!super::host_spells_data("myinternalservices2.example.com"));
}

#[test]
fn lowercase_accounts_and_phrases_in_path_segments_are_payloads() {
    let spaced = format!("{}%20art", "abandon%20".repeat(23));
    let plussed = format!("{}+art", "abandon+".repeat(23));
    for url in [
        "https://collect.example.test/?iban=gb82west12345698765432".to_owned(),
        format!("https://collect.example.test/drop/{spaced}"),
        format!("https://collect.example.test/{plussed}/x"),
    ] {
        assert!(carries(&url), "{url}");
    }
    let slug = format!("{}-art", "abandon-".repeat(23));
    for url in [
        // Lowercase with the shape but not the country's length.
        "https://search.example.test/?q=gb82west1234569876543".to_owned(),
        "https://search.example.test/?q=gb82west12345698765433".to_owned(),
        format!("https://blog.example.test/posts/{slug}"),
    ] {
        assert!(!carries(&url), "{url}");
    }
}

#[test]
fn an_encoded_phrase_and_a_query_name_are_read_as_payloads() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let phrase = format!("{}art", "abandon ".repeat(23));
    let encoded = URL_SAFE_NO_PAD.encode(phrase);
    assert!(carries(&format!(
        "https://collect.example.test/?m={encoded}"
    )));
    assert!(carries(
        "https://collect.example.test/?GB82WEST12345698765432=1"
    ));
    assert!(!carries("https://search.example.test/?page=2&sort=asc"));
}
