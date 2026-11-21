//! `hol-guard context usage` and `hol-guard context lean`: the usage meter
//! and Codex's lean-session switch, reached through the resident's runner
//! authority like the dashboard reaches them.

use std::io::Write;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const USAGE_SCHEMA: &str = "guard-context-usage-meter.v1";
const LEAN_SCHEMA: &str = "guard-codex-lean-sessions.v1";
const CONFIG_UNAVAILABLE: &str = "codex_config_unavailable";
/// The request may have reached the resident, but no answer came back.
const CONFIG_UNCONFIRMED: &str = "codex_config_unconfirmed";
/// `runner_authority`'s code for a request that got no usable answer.
const NO_ANSWER: &str = "native_runner_authority_unavailable";
const CALL_TIMEOUT: Duration = Duration::from_secs(5);
/// The first count of a long history runs in the background; ask again until it ends.
const POLL: Duration = Duration::from_millis(500);
const WAIT: Duration = Duration::from_secs(600);

/// A folder setting as the tools read it from this working folder: a
/// relative folder made absolute, a `~` folder left for the meter to expand.
fn folder_setting(name: &str) -> Option<String> {
    let raw = std::env::var(name).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with('~') {
        return Some(raw);
    }
    std::path::absolute(trimmed)
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

fn home_dir() -> Option<String> {
    crate::claude_hook_bridge::home_directory().map(|home| home.to_string_lossy().into_owned())
}

pub(super) fn usage(home: &str, as_json: bool, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let answer = home_dir().and_then(|home_dir| {
        let args = json!({
            "op": "read",
            "home_dir": home_dir,
            "codex_home": folder_setting("CODEX_HOME"),
            "claude_config_dir": folder_setting("CLAUDE_CONFIG_DIR"),
            "text": !as_json,
        });
        read_usage(home, &args, as_json, err)
    });
    let ready = answer.as_ref().and_then(|answer| {
        answer
            .get("usage")
            .filter(|state| state.get("state").and_then(Value::as_str) == Some("ready"))
            .and_then(Value::as_object)
            .map(|state| (answer, state))
    });
    let Some((answer, state)) = ready else {
        let _ = if as_json {
            writeln!(
                out,
                "{}",
                json!({"schema": USAGE_SCHEMA, "state": "unavailable"})
            )
        } else {
            writeln!(
                out,
                "Guard could not read the usage records on this computer."
            )
        };
        return 1;
    };
    if as_json {
        let mut shown = state.clone();
        shown.insert(
            "savings".into(),
            answer.get("savings").cloned().unwrap_or(Value::Null),
        );
        let _ = writeln!(out, "{}", Value::Object(shown));
    } else {
        let text = answer.get("text").and_then(Value::as_str).unwrap_or("");
        let _ = out.write_all(text.as_bytes());
    }
    0
}

fn read_usage(home: &str, args: &Value, as_json: bool, err: &mut dyn Write) -> Option<Value> {
    let deadline = Instant::now() + WAIT;
    let mut told = false;
    loop {
        let answer = crate::context_assistance_client::runner_authority(
            home,
            "context_usage",
            args.clone(),
            CALL_TIMEOUT,
        )
        .ok()?;
        let state = answer.get("usage").filter(|state| state.is_object())?;
        if state.get("state").and_then(Value::as_str) != Some("counting")
            || Instant::now() >= deadline
        {
            return Some(answer);
        }
        if !as_json && !told {
            let _ = writeln!(
                err,
                "Counting. The first count of a long history can take a minute."
            );
            told = true;
        }
        std::thread::sleep(POLL);
    }
}

pub(super) fn lean(
    home: &str,
    action: &str,
    limit: Option<i64>,
    as_json: bool,
    out: &mut dyn Write,
) -> i32 {
    let answer = home_dir()
        .map(|home_dir| {
            let args = json!({
                "switch": "lean",
                "action": action,
                "home_dir": home_dir,
                "codex_home": folder_setting("CODEX_HOME"),
                "limit": limit,
                "text": !as_json,
            });
            // A lost answer does not show that the switch was left alone.
            crate::context_assistance_client::runner_authority(
                home,
                "codex_config",
                args,
                CALL_TIMEOUT,
            )
            .unwrap_or_else(|code| {
                let code = if code == NO_ANSWER {
                    CONFIG_UNCONFIRMED
                } else {
                    CONFIG_UNAVAILABLE
                };
                json!({"ok": false, "code": code, "text": null})
            })
        })
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({"ok": false, "code": CONFIG_UNAVAILABLE, "text": null}));
    let text = answer
        .get("text")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty());
    if answer.get("ok") == Some(&Value::Bool(true)) {
        let _ = if as_json {
            writeln!(out, "{}", answer.get("state").unwrap_or(&Value::Null))
        } else {
            out.write_all(text.unwrap_or("").as_bytes())
        };
        return 0;
    }
    let code = answer
        .get("code")
        .and_then(Value::as_str)
        .filter(|code| !code.is_empty())
        .unwrap_or(CONFIG_UNAVAILABLE);
    let _ = if as_json {
        writeln!(
            out,
            "{}",
            json!({"schema": LEAN_SCHEMA, "status": "error", "code": code})
        )
    } else {
        writeln!(
            out,
            "{}",
            text.map_or_else(|| lean_failure(code), str::to_owned)
        )
    };
    1
}

/// What to tell a person when the switch gave no text of its own.
pub(super) fn lean_failure(code: &str) -> String {
    if code == CONFIG_UNCONFIRMED {
        return "Guard sent the change but got no answer, so it cannot tell whether the Codex \
config changed. Check it before trying again."
            .to_owned();
    }
    format!("Guard could not change the Codex config ({code}). Nothing was changed.")
}
