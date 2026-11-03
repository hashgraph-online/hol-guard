//! `ExtensionControlTerminal` - wire contract for the resident op that decides
//! whether a session may confirm a first extension-control enrollment.
//!
//! The op is pure. The caller holds the descriptors and the environment of the
//! session in question, so it runs the probes and ships what they returned
//! verbatim; the resident reads those bytes and answers with the verdict. Every
//! field is always present on the wire, because a field that could be omitted
//! would digest differently on each side of the call and the reply would never
//! bind to the request that asked for it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const EXTENSION_CONTROL_TERMINAL_REQUEST_SCHEMA: &str =
    "guard-extension-control-terminal-request.v1";
/// Schema discriminator for the result.
pub const EXTENSION_CONTROL_TERMINAL_RESULT_SCHEMA: &str =
    "guard-extension-control-terminal-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const EXTENSION_CONTROL_TERMINAL_FEATURE: &str = "extension-control-terminal-v1";
/// Largest canonical request serialization the op will accept.
pub const EXTENSION_CONTROL_TERMINAL_MAX_BYTES: usize = 256 * 1024;

/// What the caller may do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionControlTerminalVerdictV1 {
    /// Proven local and interactive: the caller may prompt for confirmation.
    Local,
    /// The session is remote, or its locality could not be proven.
    RemoteTerminal,
    /// There is no interactive terminal to confirm through.
    InteractiveLocalTerminal,
    /// Input and control name different terminal sessions.
    SingleTerminal,
}

impl ExtensionControlTerminalVerdictV1 {
    /// The wire name the result carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::RemoteTerminal => "remote_terminal",
            Self::InteractiveLocalTerminal => "interactive_local_terminal",
            Self::SingleTerminal => "single_terminal",
        }
    }
}

/// What the POSIX probes returned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PosixTerminalSignalsV1 {
    /// Whether `/dev/tty` opened at all.
    pub controlling_terminal_opened: bool,
    /// `os.isatty` of the controlling-terminal descriptor.
    pub controlling_terminal_is_tty: bool,
    /// Whether stdin is a terminal.
    pub stdin_is_tty: bool,
    /// Whether stdin and `/dev/tty` share a foreground process group. Null
    /// when stdin is not a terminal and the comparison was never made.
    pub descriptors_share_session: Option<bool>,
    /// The device the verdict is about: stdin's when stdin is a terminal,
    /// otherwise `/dev/tty`'s.
    pub terminal_name: String,
    /// The caller's login name, null when the password database had none.
    pub login_name: Option<String>,
    /// `who`'s stdout, null when it could not be run.
    pub who_output: Option<String>,
    /// `loginctl show-session self --property=Remote --value`'s stdout, null
    /// when it could not be run.
    pub logind_remote: Option<String>,
    /// The terminal's owning UID, null when it could not be stat'd.
    pub terminal_owner_uid: Option<u32>,
    /// Whether the terminal is a character device, null with the UID.
    pub terminal_is_char_device: Option<bool>,
    /// The caller's effective UID.
    pub effective_uid: u32,
}

/// What the Windows probes returned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WindowsTerminalSignalsV1 {
    /// Whether both stdin and stdout are terminals with readable descriptors.
    pub stdio_is_tty: bool,
    /// Whether both console descriptors answered `GetConsoleMode`.
    pub console_descriptors_interactive: bool,
    /// `%SESSIONNAME%`.
    pub session_name: String,
    /// `%CLIENTNAME%`.
    pub client_name: String,
    /// `GetSystemMetrics(SM_REMOTESESSION)` as a flag, null when the call
    /// could not be made.
    pub remote_session_metric: Option<bool>,
    /// `WTSClientProtocolType`, null when the query failed or answered with
    /// fewer bytes than the value occupies.
    pub wts_protocol_type: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlTerminalRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// The remote-terminal environment variables the caller found set and
    /// non-empty, in the order they are checked.
    pub remote_environment: Vec<String>,
    /// The POSIX probes, or null on Windows.
    pub posix: Option<PosixTerminalSignalsV1>,
    /// The Windows probes, or null on POSIX.
    pub windows: Option<WindowsTerminalSignalsV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlTerminalResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_extension_control_terminal_*` failure codes.
    pub code: String,
    /// `{"verdict": "local" | "remote_terminal" | "interactive_local_terminal"
    /// | "single_terminal"}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
