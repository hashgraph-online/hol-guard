//! `desktop-notification --stdin`: show one approval notification, or run
//! macOS notification setup (`guard/desktop_notifications.py` keeps the
//! once-per-request bookkeeping).
//!
//! - macOS: a Homebrew `terminal-notifier` at a fixed trusted path when one
//!   is installed, otherwise `osascript`. Setup sends a preview, opens the
//!   Notifications settings pane, and records that it prompted.
//! - Windows: a PowerShell toast whose text travels as single-quoted literals.
//! - Elsewhere nothing is shown.
//!
//! Every notifier runs with no stdin, no output and a hard timeout. A launch
//! failure, a non-zero exit or a timeout reads as not shown.

use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{json, Value};

const SCHEMA: &str = "desktop-notification.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const SETTINGS_URL: &str = "x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=fr.julienxx.oss.terminal-notifier";
const OSASCRIPT: &str = "/usr/bin/osascript";
const OPEN: &str = "/usr/bin/open";
const TRUSTED_TERMINAL_NOTIFIERS: [&str; 2] = [
    "/opt/homebrew/bin/terminal-notifier",
    "/usr/local/bin/terminal-notifier",
];
const DEFAULT_WINDOWS_ROOT: &str = r"C:\Windows";
const SETUP_STATE_FILE: &str = "desktop-notifications.json";
const SUBTITLE: &str = "Action needs approval";
const MACOS_TIMEOUT: Duration = Duration::from_secs(3);
const WINDOWS_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Send {
        schema: String,
        notification: Notification,
    },
    Setup {
        schema: String,
        guard_home: String,
        approval_url: String,
        force: bool,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Notification {
    request_id: String,
    title: String,
    message: String,
    approval_url: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Platform {
    MacOs,
    Windows,
    Other,
}

impl Platform {
    fn current() -> Self {
        match std::env::consts::OS {
            "macos" => Self::MacOs,
            "windows" => Self::Windows,
            _ => Self::Other,
        }
    }
}

/// The process and filesystem effects one request has, so tests can record
/// the notifier commands instead of showing them.
trait Host {
    /// Whether `program` ran to a zero exit within `timeout`.
    fn run(&mut self, program: &str, args: &[&str], timeout: Duration) -> bool;
    fn is_file(&self, path: &str) -> bool;
    /// A fresh token that keeps two notifications from sharing a group.
    fn token(&mut self) -> String;
    fn system_root(&self) -> Option<String>;
}

struct SystemHost;

impl Host for SystemHost {
    fn run(&mut self, program: &str, args: &[&str], timeout: Duration) -> bool {
        let Ok(mut child) = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            return false;
        };
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return status.success(),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
            }
        }
    }

    fn is_file(&self, path: &str) -> bool {
        fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
    }

    fn token(&mut self) -> String {
        let mut bytes = [0_u8; 16];
        if getrandom::fill(&mut bytes).is_err() {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            bytes = nanos.to_le_bytes();
        }
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn system_root(&self) -> Option<String> {
        std::env::var("SYSTEMROOT").ok()
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "desktop-notification"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "desktop_notification_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("desktop_notification_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let answer = answer(&request, Platform::current(), &mut SystemHost)?;
    Ok(answer.to_string().into_bytes())
}

fn invalid() -> String {
    "desktop_notification_request_invalid".to_owned()
}

fn answer(request: &Request, platform: Platform, host: &mut impl Host) -> Result<Value, String> {
    match request {
        Request::Send {
            schema,
            notification,
        } if schema == SCHEMA => Ok(json!({ "sent": send(notification, platform, host) })),
        Request::Setup {
            schema,
            guard_home,
            approval_url,
            force,
        } if schema == SCHEMA && Path::new(guard_home).is_absolute() => Ok(setup(
            Path::new(guard_home),
            approval_url,
            *force,
            platform,
            host,
        )),
        _ => Err(invalid()),
    }
}

fn send(notification: &Notification, platform: Platform, host: &mut impl Host) -> bool {
    match platform {
        Platform::MacOs => send_macos(notification, host),
        Platform::Windows => {
            let powershell = windows_powershell_path(host.system_root().as_deref());
            let script = windows_toast_script(notification);
            host.run(
                &powershell,
                &[
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    &script,
                ],
                WINDOWS_TIMEOUT,
            )
        }
        Platform::Other => false,
    }
}

fn send_macos(notification: &Notification, host: &mut impl Host) -> bool {
    if let Some(notifier) = trusted_terminal_notifier(&*host) {
        let group = format!("hol-guard-{}-{}", notification.request_id, host.token());
        return host.run(
            notifier,
            &[
                "-title",
                &notification.title,
                "-subtitle",
                SUBTITLE,
                "-message",
                &notification.message,
                "-open",
                &notification.approval_url,
                "-group",
                &group,
                "-sound",
                "default",
                "-ignoreDnD",
            ],
            MACOS_TIMEOUT,
        );
    }
    let message = format!(
        "{} Open: {}",
        notification.message, notification.approval_url
    );
    let script = format!(
        "display notification \"{}\" with title \"{}\" subtitle \"{SUBTITLE}\" sound name \"default\"",
        escape_osascript(&message),
        escape_osascript(&notification.title),
    );
    host.run(OSASCRIPT, &["-e", &script], MACOS_TIMEOUT)
}

/// Only a notifier at a fixed Homebrew path runs; one found anywhere else on
/// a search path could be anything.
fn trusted_terminal_notifier(host: &impl Host) -> Option<&'static str> {
    TRUSTED_TERMINAL_NOTIFIERS
        .into_iter()
        .find(|path| host.is_file(path))
}

/// Prompts once: a recorded prompt is not repeated unless `force` asks.
fn setup(
    guard_home: &Path,
    approval_url: &str,
    force: bool,
    platform: Platform,
    host: &mut impl Host,
) -> Value {
    if platform != Platform::MacOs {
        return json!({
            "supported": false,
            "preview_sent": false,
            "settings_opened": false,
            "settings_url": null,
            "already_prompted": false,
            "notifier_path": null,
        });
    }
    let state_path = guard_home.join(SETUP_STATE_FILE);
    let already_prompted = state_path.exists();
    let notifier_path = trusted_terminal_notifier(&*host);
    if already_prompted && !force {
        return json!({
            "supported": true,
            "preview_sent": false,
            "settings_opened": false,
            "settings_url": SETTINGS_URL,
            "already_prompted": true,
            "notifier_path": notifier_path,
        });
    }
    let preview = Notification {
        request_id: format!("notification-setup-{}", host.token()),
        title: "HOL Guard notifications".to_owned(),
        message: "Enable alerts for approval requests from HOL Guard.".to_owned(),
        approval_url: approval_url.to_owned(),
    };
    let preview_sent = send_macos(&preview, host);
    let settings_opened = host.run(OPEN, &[SETTINGS_URL], MACOS_TIMEOUT);
    if settings_opened {
        let state = json!({
            "opened_at": utc_now(),
            "settings_url": SETTINGS_URL,
            "preview_sent": preview_sent,
            "settings_opened": settings_opened,
            "notifier_path": notifier_path,
        });
        // The record only stops a repeat prompt, so failing to write it is
        // not a setup failure.
        if fs::create_dir_all(guard_home).is_ok() {
            if let Ok(text) = serde_json::to_string_pretty(&state) {
                let _ = fs::write(&state_path, text);
            }
        }
    }
    json!({
        "supported": true,
        "preview_sent": preview_sent,
        "settings_opened": settings_opened,
        "settings_url": SETTINGS_URL,
        "already_prompted": already_prompted,
        "notifier_path": notifier_path,
    })
}

fn utc_now() -> String {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_micros());
    crate::policy_bundle_time::micros_to_utc_isoformat(i64::try_from(micros).unwrap_or(0), "+00:00")
        .unwrap_or_default()
}

fn escape_osascript(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// `<root>\System32\WindowsPowerShell\v1.0\powershell.exe`, where the root
/// is the given one only when it is `<drive>:\Windows`.
fn windows_powershell_path(system_root: Option<&str>) -> String {
    format!(
        r"{}\System32\WindowsPowerShell\v1.0\powershell.exe",
        trusted_windows_root(system_root)
    )
}

fn trusted_windows_root(system_root: Option<&str>) -> String {
    let Some(raw) = system_root else {
        return DEFAULT_WINDOWS_ROOT.to_owned();
    };
    let mut parts = raw
        .split(['\\', '/'])
        .filter(|part| !part.is_empty() && *part != ".");
    let (Some(drive), Some(windows), None) = (parts.next(), parts.next(), parts.next()) else {
        return DEFAULT_WINDOWS_ROOT.to_owned();
    };
    let drive_bytes = drive.as_bytes();
    let is_drive =
        drive_bytes.len() == 2 && drive_bytes[0].is_ascii_alphabetic() && drive_bytes[1] == b':';
    if is_drive && windows.eq_ignore_ascii_case("windows") && raw.starts_with(drive) {
        format!(r"{drive}\{windows}")
    } else {
        DEFAULT_WINDOWS_ROOT.to_owned()
    }
}

fn windows_toast_script(notification: &Notification) -> String {
    let title = powershell_literal(&notification.title);
    let message = powershell_literal(&notification.message);
    let url = powershell_literal(&notification.approval_url);
    format!(
        "$Title = '{title}'
$Message = '{message}'
$Url = '{url}'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$Template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02
$Xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($Template)
$TextNodes = $Xml.GetElementsByTagName('text')
$TextNodes.Item(0).AppendChild($Xml.CreateTextNode($Title)) > $null
$TextNodes.Item(1).AppendChild($Xml.CreateTextNode($Message)) > $null
$ToastNode = $Xml.GetElementsByTagName('toast').Item(0)
$ToastNode.SetAttribute('launch', $Url)
$Actions = $Xml.CreateElement('actions')
$OpenAction = $Xml.CreateElement('action')
$OpenAction.SetAttribute('content', 'Open approval')
$OpenAction.SetAttribute('arguments', $Url)
$OpenAction.SetAttribute('activationType', 'protocol')
$Actions.AppendChild($OpenAction) > $null
$ToastNode.AppendChild($Actions) > $null
$Toast = [Windows.UI.Notifications.ToastNotification]::new($Xml)
$Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier()
$Notifier.Show($Toast)"
    )
}

/// The body of a PowerShell single-quoted literal. PowerShell closes such a
/// literal on the ASCII apostrophe and on the typographic single quotes
/// U+2018 to U+201B, so each one is doubled into a literal apostrophe.
fn powershell_literal(value: &str) -> String {
    let mut literal = String::with_capacity(value.len());
    for character in unescape_html(value).chars() {
        match character {
            '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}' => literal.push_str("''"),
            other => literal.push(other),
        }
    }
    literal
}

/// Decode the character references approval text can carry: numeric ones
/// and the five XML names. Anything else is left as written.
fn unescape_html(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('&') {
        decoded.push_str(&rest[..start]);
        rest = &rest[start..];
        let reference = rest[1..]
            .find(';')
            .filter(|end| *end <= 10)
            .and_then(|end| decode_reference(&rest[1..=end]).map(|character| (end, character)));
        if let Some((end, character)) = reference {
            decoded.push(character);
            rest = &rest[end + 2..];
        } else {
            decoded.push('&');
            rest = &rest[1..];
        }
    }
    decoded.push_str(rest);
    decoded
}

fn decode_reference(name: &str) -> Option<char> {
    let code = if let Some(hex) = name.strip_prefix("#x").or_else(|| name.strip_prefix("#X")) {
        u32::from_str_radix(hex, 16).ok()?
    } else if let Some(decimal) = name.strip_prefix('#') {
        decimal.parse().ok()?
    } else {
        return match name {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => None,
        };
    };
    char::from_u32(code).filter(|character| *character != '\0')
}

#[cfg(test)]
#[path = "desktop_notification_tests.rs"]
mod tests;
