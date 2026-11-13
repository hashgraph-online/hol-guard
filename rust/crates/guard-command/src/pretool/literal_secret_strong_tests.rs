use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use super::holds_proven_secret;

/// Test credentials are assembled at run time so that secret scanners
/// reading this file do not mistake them for leaked ones.
fn joined(parts: &[&str]) -> String {
    parts.concat()
}

#[test]
fn credentials_proven_by_their_context_are_secrets() {
    let pair = STANDARD.encode(joined(&["som:", "nzgjd"]));
    for text in [
        format!(
            "auth = base64.b64encode(b'yumatt:{}').decode('ascii')",
            joined(&["aja", "hrq"])
        ),
        format!("withHeader(\"Authorization\", \"BASIC {pair}\")"),
        format!("headers['Authorization'] = 'basic {pair}'"),
        format!(
            "psql -c \"ALTER ROLE postgres PASSWORD '{}'; SELECT 1\"",
            joined(&["vrkn-", "psfjianq"])
        ),
        format!(
            "CREATE USER app WITH PASSWORD '{}';",
            joined(&["Rk7q", "Wm2x"])
        ),
        format!(
            "SECRET_KEY = '{}'",
            joined(&["dyv8cxk7dv97*t=m&jeh;", "+1$9de=-#xje$xv^#@nrhqcb!^5rc@u*b"])
        ),
        format!(
            "details.setClientSecret(\"{}\");",
            joined(&["38b62b0e9a4c71d5", "b2f8a6e03c9d1f47"])
        ),
        format!(
            "  encrypted_access_token_iv: \"{}\\n\"",
            joined(&["PSX8wcWq", "FPMbWlem"])
        ),
        format!(
            "o.CookieSecret = \"{}\"",
            joined(&["WPYrHNqTzL", "kVbE4mRxQs=="])
        ),
        format!(
            "  authorization_token: '{}',",
            joined(&["kJLpygkj", "FMInDi=="])
        ),
        format!(
            ".oauth_verifier(\"{}\")",
            joined(&["cSde7aQw9Lm3Xp", "Rt5Vb2Nk8Hz4Jy6G"])
        ),
    ] {
        assert!(holds_proven_secret(&text), "{text}");
    }
}

#[test]
fn placeholders_and_references_are_not_proven_secrets() {
    let words = STANDARD.encode("hello world");
    for text in [
        "auth = base64.b64encode(b'guest:guest')".to_string(),
        "auth = base64.b64encode(b'user:password')".to_string(),
        "auth = base64.b64encode(f'{user}:{password}'.encode())".to_string(),
        "Basic authentication is enabled for this endpoint.".to_string(),
        format!("Authorization: Basic {words}"),
        "ALTER ROLE app PASSWORD 'changeme';".to_string(),
        "CREATE USER app WITH PASSWORD '${DB_PASSWORD}';".to_string(),
        "ALTER USER app PASSWORD 'xxxx';".to_string(),
        format!(
            "FAKE_TOKEN = '{}'",
            joined(&["ghu_sAsCk3Rq", "9Lm2Xp7Vb4Nz"])
        ),
        format!(
            "public_key = \"{}\"",
            joined(&["38b62b0e9a4c71d5", "b2f8a6e03c9d1f47"])
        ),
        "secret = \"0123456789abcdefghijklmnopqrstuv\"".to_string(),
        "token: \"user_session_token_value\"".to_string(),
        "password_file = \"/etc/app/secrets/db-password.txt\"".to_string(),
        "SECRET_KEY = os.environ['DJANGO_SECRET_KEY']".to_string(),
        "api_key: \"<your-api-key-goes-here>\"".to_string(),
        "secret = \"short1A!\"".to_string(),
        "client_secret: \"{{ vault_client_secret_2024 }}\"".to_string(),
        "SECRET_KEY = 'replace-this-with-a-long-random-value-9!'".to_string(),
    ] {
        assert!(!holds_proven_secret(&text), "{text}");
    }
}
