//! Exact option-value consumption and operation boundaries for curl requests.

use std::collections::BTreeSet;
use std::time::Instant;

use crate::command_structured_matchers::check_deadline;

#[path = "command_curl_targets.rs"]
mod targets;

pub(super) fn destructive_elasticsearch_operation(
    arguments: &[String],
    service_ports: &BTreeSet<u16>,
    deadline: Option<Instant>,
) -> Result<bool, &'static str> {
    let mut operations: Vec<(Option<String>, Vec<&str>)> = Vec::new();
    let mut method = None;
    let mut targets = Vec::new();
    let mut index = 0;
    let mut parse_options = true;
    while index < arguments.len() {
        check_deadline(deadline)?;
        let argument = &arguments[index];
        let lowered = argument.to_lowercase();
        if parse_options && argument == "--" {
            parse_options = false;
            index += 1;
            continue;
        }
        if !parse_options {
            targets.push(argument.trim_matches(['\'', '"']));
            index += 1;
            continue;
        }
        if lowered == "--next" {
            operations.push((method, targets));
            method = None;
            targets = Vec::new();
            index += 1;
            continue;
        }
        if lowered == "--request" && index + 1 < arguments.len() {
            method = Some(arguments[index + 1].to_lowercase());
            index += 2;
            continue;
        }
        if lowered.starts_with("--request=") {
            method = Some(
                argument
                    .split_once('=')
                    .map_or("", |(_, value)| value)
                    .to_lowercase(),
            );
            index += 1;
            continue;
        }
        if lowered == "--url" && index + 1 < arguments.len() {
            targets.push(arguments[index + 1].trim_matches(['\'', '"']));
            index += 2;
            continue;
        }
        if lowered.starts_with("--url=") {
            targets.push(
                argument
                    .split_once('=')
                    .map_or("", |(_, value)| value)
                    .trim_matches(['\'', '"']),
            );
            index += 1;
            continue;
        }
        let option = lowered.split('=').next().unwrap_or("");
        if argument.starts_with("--") && !option.is_ascii() {
            return Err("unsupported_unicode_case_mapping");
        }
        if LONG_VALUE_OPTIONS.binary_search(&option).is_ok() {
            index += if argument.contains('=') { 1 } else { 2 };
            continue;
        }
        if argument.starts_with('-') && !argument.starts_with("--") && argument.len() > 1 {
            let mut consumed_next = false;
            for (offset, short) in argument.char_indices().skip(1) {
                if !SHORT_VALUE_OPTIONS.contains(short) {
                    continue;
                }
                let mut value = &argument[offset + short.len_utf8()..];
                if value.is_empty() && index + 1 < arguments.len() {
                    value = &arguments[index + 1];
                    consumed_next = true;
                }
                if short == 'X' {
                    method = Some(value.to_lowercase());
                }
                break;
            }
            index += if consumed_next { 2 } else { 1 };
            continue;
        }
        if !argument.starts_with('-') {
            targets.push(argument.trim_matches(['\'', '"']));
        }
        index += 1;
    }
    operations.push((method, targets));
    for (method, targets) in operations {
        check_deadline(deadline)?;
        if method.as_deref() != Some("delete") {
            continue;
        }
        for target in targets {
            check_deadline(deadline)?;
            if targets::matches_target(target, service_ports)? {
                return Ok(true);
            }
        }
    }
    check_deadline(deadline)?;
    Ok(false)
}

const SHORT_VALUE_OPTIONS: &str = "ACDEFHKPQTUXYbcdemortuwxyz";
// Generated from command_curl_parsing.CURL_LONG_OPTIONS_WITH_VALUES; sorted for
// deterministic binary search. The generator is included with the test vectors.
const LONG_VALUE_OPTIONS: &[&str] = &[
    "--abstract-unix-socket",
    "--alt-svc",
    "--aws-sigv4",
    "--cacert",
    "--capath",
    "--cert",
    "--cert-type",
    "--ciphers",
    "--config",
    "--connect-timeout",
    "--connect-to",
    "--cookie",
    "--cookie-jar",
    "--create-file-mode",
    "--crlfile",
    "--curves",
    "--data",
    "--data-ascii",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    "--delegation",
    "--dns-interface",
    "--dns-ipv4-addr",
    "--dns-ipv6-addr",
    "--dns-servers",
    "--doh-url",
    "--dump-header",
    "--ech",
    "--egd-file",
    "--engine",
    "--etag-compare",
    "--etag-save",
    "--expect100-timeout",
    "--form",
    "--form-string",
    "--ftp-account",
    "--ftp-alternative-to-user",
    "--ftp-method",
    "--ftp-port",
    "--ftp-ssl-ccc-mode",
    "--happy-eyeballs-timeout-ms",
    "--haproxy-clientip",
    "--header",
    "--hostpubmd5",
    "--hostpubsha256",
    "--hsts",
    "--interface",
    "--ip-tos",
    "--ipfs-gateway",
    "--json",
    "--keepalive-cnt",
    "--keepalive-time",
    "--key",
    "--key-type",
    "--krb",
    "--libcurl",
    "--limit-rate",
    "--local-port",
    "--login-options",
    "--mail-auth",
    "--mail-from",
    "--mail-rcpt",
    "--max-filesize",
    "--max-redirs",
    "--max-time",
    "--netrc-file",
    "--noproxy",
    "--oauth2-bearer",
    "--output",
    "--output-dir",
    "--parallel-max",
    "--parallel-max-host",
    "--pass",
    "--pinnedpubkey",
    "--preproxy",
    "--proto",
    "--proto-default",
    "--proto-redir",
    "--proxy",
    "--proxy-cacert",
    "--proxy-capath",
    "--proxy-cert",
    "--proxy-cert-type",
    "--proxy-ciphers",
    "--proxy-crlfile",
    "--proxy-header",
    "--proxy-key",
    "--proxy-key-type",
    "--proxy-pass",
    "--proxy-pinnedpubkey",
    "--proxy-service-name",
    "--proxy-tls13-ciphers",
    "--proxy-tlsauthtype",
    "--proxy-tlspassword",
    "--proxy-tlsuser",
    "--proxy-user",
    "--proxy1.0",
    "--pubkey",
    "--quote",
    "--random-file",
    "--range",
    "--rate",
    "--referer",
    "--request-target",
    "--resolve",
    "--retry",
    "--retry-delay",
    "--retry-max-time",
    "--sasl-authzid",
    "--service-name",
    "--socks4",
    "--socks4a",
    "--socks5",
    "--socks5-gssapi-service",
    "--socks5-hostname",
    "--speed-limit",
    "--speed-time",
    "--stderr",
    "--telnet-option",
    "--tftp-blksize",
    "--time-cond",
    "--tls-earlydata",
    "--tls-max",
    "--tls13-ciphers",
    "--tlsauthtype",
    "--tlspassword",
    "--tlsuser",
    "--trace",
    "--trace-ascii",
    "--trace-config",
    "--unix-socket",
    "--upload-file",
    "--upload-flags",
    "--url-query",
    "--user",
    "--user-agent",
    "--variable",
    "--vlan-priority",
    "--write-out",
];
