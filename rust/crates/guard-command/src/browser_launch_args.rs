//! A browser MCP server's launch arguments, read from the artifact metadata.
//!
//! The profile mode and the loopback quiet set (D10) both decide from these arguments. A flag
//! matches only as a whole argument or as the part before `=`, so `--isolated-x` is not
//! `--isolated` and `--shared` is never hidden behind a longer flag that shares its prefix.

use serde_json::{Map, Value};

use crate::browser_first_party_drivers::first_party_browser_drivers;

/// Launch flags that attach the browser to a remote-debugging endpoint, beyond the ones the
/// first-party profiles list.
const DEBUGGING_FLAGS: [&str; 7] = [
    "--remote-debugging-port",
    "--cdp-endpoint",
    "--cdp-port",
    "--ws-endpoint",
    "--wsEndpoint",
    "--browser-url",
    "--browserUrl",
];

/// The server's launch arguments, from every place the metadata may carry them.
pub(crate) fn launch_args<'a>(
    metadata: &'a Map<String, Value>,
) -> impl Iterator<Item = &'a str> + Clone + 'a {
    let identity_args = metadata
        .get("mcp_server_identity")
        .and_then(Value::as_object)
        .and_then(|identity| identity.get("args"))
        .and_then(Value::as_array)
        .map(Vec::as_slice);
    let direct_args = metadata
        .get("args")
        .and_then(Value::as_array)
        .map(Vec::as_slice);
    let server_args = metadata
        .get("server_args")
        .and_then(Value::as_array)
        .map(Vec::as_slice);
    // The relay records the server's launch only as `server_fingerprint.command`: the
    // executable, then its arguments. The identity above carries just a hash of them.
    let relay_args = metadata
        .get("server_fingerprint")
        .and_then(Value::as_object)
        .and_then(|fingerprint| fingerprint.get("command"))
        .and_then(Value::as_array)
        .and_then(|command| command.get(1..));
    [identity_args, direct_args, server_args, relay_args]
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(Value::as_str)
}

/// The flag an argument names: the whole argument, or the part before `=`.
pub(crate) fn flag_name(argument: &str) -> &str {
    argument.split_once('=').map_or(argument, |(flag, _)| flag)
}

/// Whether any launch argument names a remote-debugging or shared-profile flag, whatever other
/// flags beside it claim. Such a browser may be the user's real one, so it is never quiet.
pub(crate) fn debugging_or_shared_launch<'a>(arguments: impl Iterator<Item = &'a str>) -> bool {
    let drivers = first_party_browser_drivers();
    arguments.map(flag_name).any(|flag| {
        DEBUGGING_FLAGS.contains(&flag)
            || drivers.iter().any(|driver| {
                driver
                    .profile_flags
                    .remote_debugging
                    .iter()
                    .chain(&driver.profile_flags.shared)
                    .any(|listed| listed == flag)
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_debugging_and_shared_spelling_disqualifies() {
        for argument in [
            "--remote-debugging-port=9333",
            "--remote-debugging-pipe",
            "--cdp-endpoint",
            "--cdp-endpoint=localhost:9222",
            "--browserUrl=http://localhost:4000/",
            "--ws-endpoint",
            "--wsEndpoint=127.0.0.1:9333",
            "--shared",
            "--no-isolated",
        ] {
            assert!(
                debugging_or_shared_launch(["--isolated", argument].into_iter()),
                "{argument}"
            );
        }
    }

    #[test]
    fn unrelated_and_prefix_only_flags_do_not_disqualify() {
        assert!(!debugging_or_shared_launch(
            ["--isolated", "--port", "3000", "--headless"].into_iter()
        ));
        assert!(!debugging_or_shared_launch(
            ["--shared-memory-size=2", "--cdp-endpointish"].into_iter()
        ));
    }

    #[test]
    fn flag_name_stops_at_the_first_equals_sign() {
        assert_eq!(flag_name("--user-data-dir=/p=q"), "--user-data-dir");
        assert_eq!(flag_name("--isolated"), "--isolated");
    }
}
