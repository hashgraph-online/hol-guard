use serde_json::json;

use super::{holds_literal_secret, writes_literal_secret};

/// Test credentials are assembled at run time so that secret scanners
/// reading this file do not mistake them for leaked ones.
fn joined(parts: &[&str]) -> String {
    parts.concat()
}

#[test]
fn random_values_next_to_credential_names_are_secrets() {
    for text in [
        format!("secret_code = \"{}\"\n", joined(&["Fdyg", "nrahkfd"])),
        format!("config.JWT.Secret = \"{}\"", joined(&["jrmu", "canxhu"])),
        format!("  DB_PASSWORD: {}\n", joined(&["qeyj", "jicm"])),
        format!("  - AWS_SECRET_ACCESS_KEY={}\n", joined(&["ogpgn", "966"])),
        format!(
            "jwt-secret-key: {}",
            joined(&["OlcUMhzAu", "ZtMsxxVvKrkBh"])
        ),
        format!(
            "\"client_secret\": \"{}\"",
            joined(&["38b62b849be2", "b1bb909f13bc4e09bc4b"])
        ),
        format!("apiKey: '{}'", joined(&["jAKrQsxs1", "8a5qvzhwtM0"])),
    ] {
        assert!(holds_literal_secret(&text), "{text}");
    }
}

#[test]
fn credentials_recognised_by_shape_are_secrets() {
    let body = "A".repeat(20);
    for text in [
        format!("-----BEGIN RSA PRIVATE KEY-----\nMII{body}{body}\n-----END RSA PRIVATE KEY-----"),
        format!(
            "t = '{}.{}.{}'",
            joined(&["eyJ", "hbGciOiJIUzI1NiJ9"]),
            joined(&["eyJ", "zdWIiOiIxMjM0NTY3ODkwIn0"]),
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        ),
        format!(
            "otpauth://totp/acme?secret={}&issuer=acme",
            joined(&["SBVFH5KV", "SROV2TMO"])
        ),
        format!(
            "url = \"postgres://app:{}@db.internal/app\"",
            joined(&["Wk2t", "m3mk9x"])
        ),
        format!("nats://svc:{}@%s:%d", joined(&["pb", "xk"])),
        format!("--keystore-password \"{}\"", joined(&["wutch", "sayykay"])),
        format!(
            "GET /cb?refreshToken={}&s=2",
            joined(&["7809911bba6827edc2af", "6cd432be137294dfb5bd"])
        ),
        format!(
            "\"Apitoken\": \"{{\\\"a\\\":\\\"{}\\\"}}\"",
            joined(&["487v7538h7766", "5b45vwz6359hw055248"])
        ),
        format!("Authorization: Basic {}", joined(&["c29tOm56", "Z2pkZA=="])),
    ] {
        assert!(holds_literal_secret(&text), "{text}");
    }
}

#[test]
fn placeholders_references_and_words_are_not_secrets() {
    for text in [
        "password = \"changeme\"",
        "api_key = os.environ[\"API_KEY\"]",
        "token = getToken()",
        "secret: ${{ secrets.DEPLOY_KEY }}",
        "auth_token: <your-token-here>",
        "client_secret = \"YOUR_CLIENT_SECRET\"",
        "secrets = svc_info['Spec']['Secrets']",
        "jwt-secret = \"secret_with_at_least_32_characters\"",
        "sec-websocket-key: 'xxxxxxxxxxxxxxxxxxxxxxxx'",
        "AuthenticationProviderKey = \"JwtLads\"",
        "const newEncodedJwt = await jwt.encode({ ...jwt, token: jwtPayload })",
        "certificate-authority-data: aGVsbG8K",
        "  -cookie-secret string: the seed string for secure cookies",
        "stub_request(:post, \"https://foo:bar@api.example.com/login\")",
        "postgres://foo:yeah@example.com:234/db",
        "amqp://guest:guest@localhost:5672",
        "Key: \"idx_fk_city_id\",",
        "export TOKEN=$(cat token.txt)",
        "let primary_key = \"user_id\";",
        "passwordField.sendKeys(\"hunter\")",
    ] {
        assert!(!holds_literal_secret(text), "{text}");
    }
}

#[test]
fn made_up_github_tokens_fail_their_checksum() {
    let token = joined(&["ghs_", "5oY4owWX1cNe5OPl0AAlOIjdS9vGTi0NBuQl"]);
    assert!(!holds_literal_secret(&format!(
        "export GITHUB_TOKEN={token}"
    )));
}

#[test]
fn file_tool_bodies_are_screened() {
    let secret = format!("client_secret = \"{}\"\n", joined(&["Fdyg", "nrahkfd"]));
    assert!(writes_literal_secret(&json!({
        "tool_input": {"file_path": "/w/app.py", "content": secret}
    })));
    assert!(writes_literal_secret(&json!({
        "tool_input": {"file_path": "/w/app.py", "old_string": "a", "new_string": secret}
    })));
    assert!(writes_literal_secret(&json!({
        "tool_input": {"file_path": "/w/app.py", "edits": [{"old_string": "a", "new_string": secret}]}
    })));
    assert!(!writes_literal_secret(&json!({
        "tool_input": {"file_path": "/w/app.py", "content": "print('hello')\n"}
    })));
}

#[test]
fn shell_commands_that_spell_out_a_secret_are_reviewed() {
    let key = joined(&["AKIA", "Z7Q3R2LM", "X9KDW4PN"]);
    let run = |command: String| {
        crate::pretool::evaluate_pre_tool_envelope(
            "claude-code",
            "PreToolUse",
            &json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "cwd": "/tmp",
                "tool_input": {"command": command}
            }),
        )
    };
    let spelled = run(format!("echo {key}"));
    assert_eq!(spelled.reason_code, "native_command_review_required");
    assert_ne!(spelled.minimum_action, "allow");
    let plain = run("echo $AWS_ACCESS_KEY_ID".to_owned());
    assert_ne!(plain.reason_code, "native_command_review_required");
}

#[test]
fn an_enabled_extension_permission_cannot_settle_a_spelled_out_secret() {
    let model = |command: String| {
        crate::parse_command(&serde_json::from_value(json!({"command": command})).unwrap()).unwrap()
    };
    let password = joined(&["Wk2t", "m3mk9x"]);
    let spelled = format!("printf 'DATABASE_URL=postgres://app:{password}@db.invalid/app\\n'");
    assert!(crate::pretool::fixed_command_floor(&model(spelled)));
    let placeholder = "printf 'DATABASE_URL=postgres://app:changeme@db.invalid/app\\n'".to_owned();
    assert!(!crate::pretool::fixed_command_floor(&model(placeholder)));
}

#[test]
fn a_key_spelled_in_unicode_escapes_is_still_a_key() {
    let key = joined(&["AKIA", "Q3EGRTL5", "KH7XWNP2"]);
    let escaped: String = key
        .chars()
        .map(|c| format!("\\u{:04x}", c as u32))
        .collect();
    assert!(holds_literal_secret(&format!(
        "{{\"aws_key\": \"{escaped}\"}}"
    )));
    let write = json!({
        "tool_name": "Write",
        "tool_input": {"file_path": "/tmp/config.json", "content": format!("{{\"key\": \"{escaped}\"}}")}
    });
    assert!(writes_literal_secret(&write));
    assert!(!holds_literal_secret(
        "{\"greeting\": \"caf\\u00e9 \\u2014 open\"}"
    ));
    assert!(!holds_literal_secret("printf '\\u0041'"));
}

#[test]
fn a_search_of_a_secrets_directory_is_reviewed() {
    let run = |command: &str| {
        crate::pretool::evaluate_pre_tool_envelope(
            "claude-code",
            "PreToolUse",
            &json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "cwd": "/tmp",
                "tool_input": {"command": command}
            }),
        )
    };
    for command in [
        "grep -i token ~/.secrets/key.txt",
        "rg password /home/dev/.secrets/key.txt",
    ] {
        assert_ne!(run(command).minimum_action, "allow", "{command}");
    }
    assert_eq!(run("grep -n secrets README.md").minimum_action, "allow");
}

#[test]
fn a_patch_that_adds_a_secret_is_a_write_of_it() {
    let value = joined(&["Fdyg", "nrah", "kfdQ", "7mzX"]);
    let codex = json!({
        "tool_name": "apply_patch",
        "tool_input": {"command": format!(
            "*** Begin Patch\n*** Update File: app/config.py\n@@\n-client_secret = None\n+client_secret = \"{value}\"\n*** End Patch\n"
        )}
    });
    assert!(writes_literal_secret(&codex));
    let omp = json!({
        "tool_name": "edit",
        "tool_input": {"input": format!("[app/config.py#AB12]\nPUT 3\n+client_secret = \"{value}\"\n")}
    });
    assert!(writes_literal_secret(&omp));
    let removed = json!({
        "tool_name": "apply_patch",
        "tool_input": {"command": format!(
            "*** Begin Patch\n*** Update File: app/config.py\n@@\n-client_secret = \"{value}\"\n+client_secret = os.environ[\"CLIENT_SECRET\"]\n*** End Patch\n"
        )}
    });
    assert!(!writes_literal_secret(&removed));
}
