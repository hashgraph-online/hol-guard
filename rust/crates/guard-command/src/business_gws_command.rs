#![forbid(unsafe_code)]

//! Narrow POSIX command preparation through the existing native shell parser.
//! This does not authenticate a resolved executable/account or authorize/send.

use crate::business_gmail_wire::{GmailSendWireErrorV1, GmailSendWireInputV1};
use crate::{parse_command, CommandModelRequestV1, MAX_COMMAND_BYTES};
use sha2::{Digest, Sha256};

/// Finite preparation errors; no private command or payload is echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GwsGmailCommandErrorV1 {
    /// Original UTF-8 command exceeded the existing native parser byte cap.
    BoundsExceeded,
    /// Empty/malformed command or missing/duplicate required payload option.
    InvalidCommand,
    /// Shell input can expand, redirect, wrap, compose or parse uncertainly.
    UnsupportedContext,
    /// Executable, route or option lies outside the pinned inline profile.
    UnsupportedRoute,
    /// The strict Gmail wire decoder rejected the recovered JSON bytes.
    Wire(GmailSendWireErrorV1),
}

/// The general matcher parser intentionally does not evaluate expansions.
/// Reject active syntax before using its tokens as exact provider input. Literal
/// single-quoted JSON can contain these characters without interpretation.
fn literal_shell_input(command: &str) -> bool {
    let mut quote = None;
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        if c == '\0' {
            return false;
        }
        match quote {
            Some('\'') => {
                if c == '\'' {
                    quote = None;
                }
            }
            Some('"') => match c {
                '"' => quote = None,
                '$' | '`' | '\r' | '\n' => return false,
                '\\' => {
                    // POSIX and the native parser both preserve backslashes
                    // before ordinary characters (including JSON n/u escapes).
                    // The native parser does not match POSIX for escaped $/`
                    // or line continuation, so those forms remain unsupported.
                    if matches!(chars.next(), None | Some('$' | '`' | '\0' | '\r' | '\n')) {
                        return false;
                    }
                }
                _ => {}
            },
            None => match c {
                '\'' | '"' => quote = Some(c),
                '$' | '`' | '*' | '?' | '[' | ']' | '~' | '{' | '}' | '(' | ')' | '<' | '>'
                | '|' | '&' | ';' | '#' | '\r' | '\n' => return false,
                '\\' => {
                    if cfg!(windows) || matches!(chars.next(), None | Some('\0' | '\r' | '\n')) {
                        return false;
                    }
                }
                _ => {}
            },
            _ => return false,
        }
    }
    quote.is_none()
}

/// Frozen original command plus decoded parameter/body bytes. Deliberately
/// lacks Debug, Serialize, Clone and mutable interfaces. A trusted producer
/// must resolve the launch/account identity and consume the frozen request;
/// executing this original shell text after approval is not managed dispatch.
pub struct GwsGmailSendCommandInputV1 {
    command: Box<str>,
    wire: GmailSendWireInputV1,
    binding: String,
}

impl GwsGmailSendCommandInputV1 {
    /// Prepare only `gws gmail users messages send` with one inline `--params`
    /// and one inline `--json`, in either order or assignment spelling. Reject
    /// every other flag, wrapper, override, expansion and compound context.
    pub fn from_owned_posix_command(command: String) -> Result<Self, GwsGmailCommandErrorV1> {
        use GwsGmailCommandErrorV1 as Error;
        if command.len() > MAX_COMMAND_BYTES {
            return Err(Error::BoundsExceeded);
        }
        if !literal_shell_input(&command) {
            return Err(Error::UnsupportedContext);
        }
        let request = CommandModelRequestV1 {
            command,
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "business-gws-inline-v1".to_owned(),
        };
        let parsed = parse_command(&request).map_err(|_| Error::InvalidCommand)?;
        if parsed.confidence != "exact"
            || parsed.uncertainty_reason.is_some()
            || parsed.segments.len() != 1
            || !parsed.wrapper_chain.is_empty()
            || parsed.path_overridden
        {
            return Err(Error::UnsupportedContext);
        }
        let segment = &parsed.segments[0];
        if !segment.environment_names.is_empty()
            || !segment.wrapper_chain.is_empty()
            || segment.pipeline_index != 0
            || segment.execution_context != "top:0"
        {
            return Err(Error::UnsupportedContext);
        }
        if segment.executable.as_deref() != Some("gws")
            || !segment
                .arguments
                .iter()
                .take(4)
                .map(String::as_str)
                .eq(["gmail", "users", "messages", "send"])
        {
            return Err(Error::UnsupportedRoute);
        }
        let mut params = None;
        let mut body = None;
        let mut args = segment.arguments[4..].iter();
        while let Some(arg) = args.next() {
            let (name, value) = match arg.split_once('=') {
                Some(pair) => pair,
                None => (
                    arg.as_str(),
                    args.next().ok_or(Error::InvalidCommand)?.as_str(),
                ),
            };
            let slot = match name {
                "--params" => &mut params,
                "--json" => &mut body,
                _ => return Err(Error::UnsupportedRoute),
            };
            if slot.replace(value.as_bytes().to_vec()).is_some() {
                return Err(Error::InvalidCommand);
            }
        }
        let wire = GmailSendWireInputV1::from_owned_json(
            params.ok_or(Error::InvalidCommand)?,
            body.ok_or(Error::InvalidCommand)?,
        )
        .map_err(Error::Wire)?;
        let mut hash = Sha256::new();
        hash.update(b"hol-guard.gws-gmail-command-input.v1\0");
        hash.update((request.command.len() as u64).to_be_bytes());
        hash.update(request.command.as_bytes());
        hash.update(wire.input_binding().as_bytes());
        Ok(Self {
            command: request.command.into_boxed_str(),
            wire,
            binding: hex::encode(hash.finalize()),
        })
    }

    /// Exact original private source; this is not an executable capability.
    pub fn command_text(&self) -> &str {
        &self.command
    }

    /// Immutable wire bytes that still need MIME/account/approval validation.
    pub fn wire_input(&self) -> &GmailSendWireInputV1 {
        &self.wire
    }

    /// Move the frozen provider bytes into the private worker's next stage.
    pub fn into_wire_input(self) -> GmailSendWireInputV1 {
        self.wire
    }

    /// Preparation identity committing the command and underlying wire binding.
    pub fn input_binding(&self) -> &str {
        &self.binding
    }
}
