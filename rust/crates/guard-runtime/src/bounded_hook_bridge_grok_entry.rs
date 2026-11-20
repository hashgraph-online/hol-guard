//! The entry points of the native Grok bridge: the generated client's argv,
//! the bootstrap config a Grok install writes without an isolated
//! interpreter, and the fail-closed answer for a client it cannot read.

use super::*;

/// How long a hook whose client this bridge cannot read waits for its input.
const UNREADABLE_CLIENT_INPUT: Duration = Duration::from_secs(5);

/// `_fail("{}")`: the answer when the hook could not be read at all.
fn fail_closed() -> i32 {
    write_stdout(&failure_stdout("{}"));
    0
}

/// The failure answer for a hook whose client this bridge cannot read,
/// rendered for the hook's own event so an observer stays non-blocking.
/// Input `route` would answer as a PreToolUse still fails as one.
fn client_unreadable_stdout(raw: &[u8]) -> String {
    let body = raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(raw);
    let text = std::str::from_utf8(body)
        .ok()
        .filter(|_| raw.len() <= MAX_HOOK_INPUT_BYTES)
        .filter(|text| {
            json_object(text).is_some_and(|payload| {
                !pretool_event_conflict(&payload) && event_labels_are_ascii(&payload)
            })
        });
    failure_stdout(text.unwrap_or("{}"))
}

/// Answer one Grok hook. `python_argv` is `[python, "-I", script, config]`.
pub(crate) fn run(python_argv: &[String], started: Instant) -> i32 {
    let constants = read_client_constants(Path::new(&python_argv[2]))
        .map(|constants| (constants.guard_home, constants.timeout_seconds));
    serve(constants, &python_argv[3], started)
}

/// A Grok hook registered as `<python> -I -c <bootstrap> <config>`, written
/// when no isolated interpreter could run the generated client. The config
/// names the Guard home and timeout the client would have held.
pub(crate) fn run_config(argument: &str, started: Instant) -> i32 {
    serve(config_constants(argument), argument, started)
}

/// Whether an install-time config is a Grok one.
pub(crate) fn names_grok(argument: &str) -> bool {
    json_object(argument)
        .is_some_and(|config| member(&config, "harness").and_then(PyVal::as_str) == Some("grok"))
}

/// The Guard home and timeout a Grok config names.
fn config_constants(argument: &str) -> Option<(String, f64)> {
    let config = json_object(argument)?;
    let guard_home = member(&config, "guard_home")?.as_str()?.to_owned();
    let timeout = crate::bounded_hook_bridge::positive_seconds(member(&config, "timeout_seconds"))?;
    Some((guard_home, timeout.as_secs_f64()))
}

/// Answer one Grok hook for the client `constants` name, a Guard home and
/// a timeout, and the install-time `argument`.
fn serve(constants: Option<(String, f64)>, argument: &str, started: Instant) -> i32 {
    let client = constants.and_then(|(guard_home, timeout_seconds)| {
        let invocation = invocation(argument, &guard_home)?;
        let budget = Duration::try_from_secs_f64(timeout_seconds).ok()?;
        Some(Client {
            guard_home: PathBuf::from(&guard_home),
            timeout_seconds,
            invocation,
            deadline: started.checked_add(budget)?,
        })
    });
    let Some(client) = client else {
        // No install writes a client this bridge cannot read, so the hook
        // fails closed rather than running Python.
        let Input::Read(raw) = read_hook_input(started + UNREADABLE_CLIENT_INPUT) else {
            return fail_closed();
        };
        write_stdout(&client_unreadable_stdout(&raw));
        return 0;
    };
    let Input::Read(raw) = read_hook_input(client.deadline) else {
        return fail_closed();
    };
    let Route::Respond { stdout, exit_code } = client.route(&raw);
    write_stdout(&stdout);
    exit_code
}

#[cfg(test)]
#[path = "bounded_hook_bridge_grok_client_tests.rs"]
mod client_tests;
