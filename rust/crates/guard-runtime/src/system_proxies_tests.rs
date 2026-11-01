use serde_json::{json, Value};

use super::*;

/// What `scutil --proxy` prints with an HTTPS proxy on its default port and
/// a disabled HTTP proxy.
const SCUTIL_OUTPUT: &str = "<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
  }
  FTPPassive : 1
  HTTPEnable : 0
  HTTPPort : 3128
  HTTPProxy : http-proxy.example
  HTTPSEnable : 1
  HTTPSProxy : https-proxy.example
}
";

fn answer(request: Value) -> Result<Value, String> {
    let bytes = run_command(serde_json::to_vec(&request).unwrap().as_slice())?;
    Ok(serde_json::from_slice(&bytes).unwrap())
}

fn dword(value: u32) -> (u32, Vec<u8>) {
    (REG_DWORD, value.to_le_bytes().to_vec())
}

fn text(value: &str) -> (u32, Vec<u8>) {
    let bytes = value
        .encode_utf16()
        .chain(Some(0))
        .flat_map(u16::to_le_bytes)
        .collect();
    (REG_SZ, bytes)
}

/// One stored registry value: its hive, its name, and its type and data.
type Stored = (Hive, &'static str, (u32, Vec<u8>));

fn proxies_from(hives: &[Stored]) -> (Map<String, Value>, Vec<(Hive, String)>) {
    let mut reads = Vec::new();
    let proxies = windows_proxies(|hive, name| {
        reads.push((hive, name.to_owned()));
        hives
            .iter()
            .find(|(found, value, _)| *found == hive && *value == name)
            .map(|(_, _, data)| data.clone())
    });
    (proxies, reads)
}

#[test]
fn scutil_reports_only_enabled_proxies_with_default_ports() {
    assert_eq!(
        Value::Object(macos_proxies(SCUTIL_OUTPUT)),
        json!({"https": "http://https-proxy.example:443"})
    );
    let enabled = SCUTIL_OUTPUT.replace("HTTPEnable : 0", "HTTPEnable : 1");
    assert_eq!(
        Value::Object(macos_proxies(&enabled)),
        json!({
            "http": "http://http-proxy.example:3128",
            "https": "http://https-proxy.example:443",
        })
    );
    assert!(macos_proxies("").is_empty());
    assert!(macos_proxies("HTTPSEnable : 1\n").is_empty());
}

#[test]
fn the_last_repeated_scutil_key_wins() {
    let output = "HTTPSEnable : 1\nHTTPSProxy : first.example\nHTTPSProxy : second.example  \n";
    assert_eq!(
        Value::Object(macos_proxies(output)),
        json!({"https": "http://second.example:443"})
    );
}

#[test]
fn windows_falls_back_to_the_machine_hive() {
    let (proxies, reads) = proxies_from(&[
        (Hive::LocalMachine, "ProxyEnable", dword(1)),
        (
            Hive::LocalMachine,
            "ProxyServer",
            text("proxy.example:8080"),
        ),
    ]);
    assert_eq!(
        Value::Object(proxies),
        json!({
            "http": "http://proxy.example:8080",
            "https": "http://proxy.example:8080",
        })
    );
    assert_eq!(reads[0], (Hive::CurrentUser, "ProxyEnable".to_owned()));
}

#[test]
fn a_disabled_user_proxy_defers_to_the_machine_and_an_enabled_one_wins() {
    let machine = (Hive::LocalMachine, "ProxyServer", text("machine.example:1"));
    let (proxies, _) = proxies_from(&[
        (Hive::CurrentUser, "ProxyEnable", dword(0)),
        (Hive::CurrentUser, "ProxyServer", text("user.example:2")),
        (Hive::LocalMachine, "ProxyEnable", dword(1)),
        machine.clone(),
    ]);
    assert_eq!(proxies["http"], "http://machine.example:1");
    let (proxies, reads) = proxies_from(&[
        (Hive::CurrentUser, "ProxyEnable", dword(1)),
        (Hive::CurrentUser, "ProxyServer", text("user.example:2")),
        (Hive::LocalMachine, "ProxyEnable", dword(1)),
        machine,
    ]);
    assert_eq!(proxies["http"], "http://user.example:2");
    assert!(reads.iter().all(|(hive, _)| *hive == Hive::CurrentUser));
}

#[test]
fn per_scheme_servers_keep_only_http_and_https() {
    let (proxies, _) = proxies_from(&[
        (Hive::CurrentUser, "ProxyEnable", dword(1)),
        (
            Hive::CurrentUser,
            "ProxyServer",
            text("ftp=ftp.example:21;http=web.example:80;https=;socks=s.example:1"),
        ),
    ]);
    assert_eq!(
        Value::Object(proxies),
        json!({"http": "http://web.example:80"})
    );
}

#[test]
fn a_server_that_is_not_text_or_a_hive_that_is_unreadable_is_no_proxy() {
    let (proxies, _) = proxies_from(&[
        (Hive::CurrentUser, "ProxyEnable", dword(1)),
        (Hive::CurrentUser, "ProxyServer", dword(7)),
    ]);
    assert!(proxies.is_empty());
    let (proxies, _) = proxies_from(&[(Hive::CurrentUser, "ProxyServer", text("x:1"))]);
    assert!(proxies.is_empty());
}

#[test]
fn registry_truthiness_follows_winreg_values() {
    assert!(!registry_truthy(REG_DWORD, &0u32.to_le_bytes()));
    assert!(registry_truthy(REG_DWORD, &1u32.to_le_bytes()));
    assert!(registry_truthy(REG_QWORD, &(1u64 << 40).to_le_bytes()));
    assert!(!registry_truthy(REG_SZ, &[0, 0]));
    assert!(registry_truthy(REG_SZ, &text("1").1));
    assert!(!registry_truthy(REG_MULTI_SZ, &[0, 0, 0, 0]));
    assert!(!registry_truthy(3, &[]));
    assert!(registry_truthy(3, &[0]));
}

#[test]
fn requests_with_another_schema_or_extra_fields_are_refused() {
    let invalid = Err("system_proxies_request_invalid".to_owned());
    assert_eq!(answer(json!({"schema": "other"})), invalid);
    assert_eq!(
        answer(json!({"schema": SCHEMA, "platform": "macos"})),
        invalid
    );
    let answered = answer(json!({"schema": SCHEMA})).unwrap();
    assert_eq!(answered["ok"], true);
    assert!(answered["proxies"].is_object());
}
