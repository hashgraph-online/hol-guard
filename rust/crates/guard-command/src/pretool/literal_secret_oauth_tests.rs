use super::holds_oauth_credential;

/// Test credentials are assembled at run time so that secret scanners
/// reading this file do not mistake them for leaked ones.
fn joined(parts: &[&str]) -> String {
    parts.concat()
}

#[test]
fn oauth_credential_parameters_with_filled_values_are_secrets() {
    let token = joined(&["qk4h7", "tz2wm9", "rbx3p"]);
    let signature = joined(&["Hn7Rk2q", "Wm4xZt9", "Lp3Bv8%2", "BcY5Jd%3D"]);
    let consumer = joined(&["Rdimkh", "%2B", "Vqzwnt"]);
    let short = joined(&["qk4h", "7tz2"]);
    for text in [
        format!("+ \"                oauth_token=\\\"{token}\\\",\\n\""),
        format!("Authorization: OAuth oauth_signature=\"{signature}\""),
        format!("expect(header).to match(/OAuth\\ oauth_consumer_key=\"{consumer}\",.*/)"),
        format!("params.put(\"oauth_nonce\", \"{token}\");"),
        format!("{{\"oauth_token_secret\": \"{token}\"}}"),
        format!("params.put(\"oauth_token\", \"{short}\");"),
    ] {
        assert!(holds_oauth_credential(&text), "{text}");
    }
}

#[test]
fn a_signature_base_string_carrying_credentials_is_a_secret() {
    let key = joined(&["dpfzqk", "rmvwhtcn"]);
    let nonce = joined(&["8318467", "427418", "11234"]);
    let text = format!(
        "String base = \"GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3D{key}%26oauth_nonce%3D{nonce}%26oauth_signature_method%3DHMAC-SHA1\";"
    );
    assert!(holds_oauth_credential(&text), "{text}");
}

#[test]
fn an_inline_cipher_key_is_a_secret() {
    let key = joined(&["kzqvwmrtbx", "hjdnplgcfs", "yaeuoi"]);
    let text = format!(
        "SecretKeySpec spec = new SecretKeySpec(\"{key}\".getBytes(\"UTF-8\"), \"HmacSHA1\");"
    );
    assert!(holds_oauth_credential(&text), "{text}");
}

#[test]
fn oauth_settings_names_templates_and_placeholders_are_not_secrets() {
    for text in [
        "+ \"                oauth_signature_method=\\\"HMAC-SHA1\\\",\\n\"",
        "params.put(\"oauth_signature_method\", \"HMAC-SHA1\");",
        "\"oauth_timestamp\": \"1318622958\"",
        "headers = { oauth_token: \"#{oauth_token}\" }",
        "params.put(\"oauth_token\", \"sessionValue123${token}\");",
        "params.put(\"oauth_token\", \"prefix9Kq#{token}\");",
        "oauth_token=\"token12\"",
        "oauth_token=\"token123\"",
        "params.put(\"oauth_nonce\", \"abc12345\");",
        "oauth_nonce=\"98765432\"",
        "oauth_token=\"${OAUTH_TOKEN_FROM_ENVIRONMENT}\"",
        "oauth_token=\"{{ oauth_token_value }}\"",
        "oauth_consumer_key=\"your_consumer_key_here\"",
        "oauth_token=\"AccessTokenValue\"",
        "oauth_token=\"xxxxxxxxxxxxxxxx\"",
        "attr_reader :oauth_token, :oauth_id, :oauth_secret",
        "urn:ietf:wg:oauth:2.0:oob",
        "oauth_signature: the request signature, computed per RFC 5849",
    ] {
        assert!(!holds_oauth_credential(text), "{text}");
    }
}

#[test]
fn a_base_string_without_credential_values_is_not_a_secret() {
    for text in [
        "GET&https%3A%2F%2Fapi.example.net%2Fitems&page%3D2%26sort%3Dname",
        "POST&https%3A%2F%2Fapi.example.net%2Fitems&oauth_token%3D%24%7BTOKEN%7D",
        "the signature covers oauth_consumer_key%3D and oauth_nonce%3D values",
    ] {
        assert!(!holds_oauth_credential(text), "{text}");
    }
}

#[test]
fn cipher_keys_built_elsewhere_or_trivial_are_not_secrets() {
    for text in [
        "new SecretKeySpec(keyBytes, \"AES\")",
        "new SecretKeySpec(\"secret\".getBytes(), \"HmacSHA256\")",
        "new SecretKeySpec(\"0123456789abcdef\".getBytes(), \"AES\")",
        "new SecretKeySpec(\"aaaaaaaaaaaaaaaa\".getBytes(), \"AES\")",
        "new SecretKeySpec(\"changeme-changeme\".getBytes(), \"AES\")",
    ] {
        assert!(!holds_oauth_credential(text), "{text}");
    }
}
