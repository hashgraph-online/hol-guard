//! The options a local CLI call passes, and how they refine its grant.

use rusqlite::{params, Connection};

use super::{command_state, CommandState, ROOT_COMMAND_ID, STORE_UNAVAILABLE};

/// The option names an invocation passes, from the arguments after its
/// runner or script path: every argument that starts with `-`, up to a bare
/// `--`, cut at `=`. A spelling no catalog can hold, or a call past
/// `MAX_OPTIONS`, reads as [`UNNAMED_OPTION`], which no catalog row matches.
pub(crate) fn invocation_options(arguments: &[String]) -> Vec<String> {
    let mut options: Vec<String> = Vec::new();
    for argument in arguments {
        if argument == "--" {
            break;
        }
        if argument == "-" || !argument.starts_with('-') {
            continue;
        }
        let name = argument.split('=').next().unwrap_or_default();
        let option = if crate::local_cli_help::is_option_name(name) {
            name.to_owned()
        } else {
            UNNAMED_OPTION.to_owned()
        };
        if options.contains(&option) {
            continue;
        }
        if options.len() == MAX_OPTIONS - 1 {
            options.push(UNNAMED_OPTION.to_owned());
            break;
        }
        options.push(option);
    }
    options
}

/// Most option names one request carries. A longer call is cut short with
/// [`UNNAMED_OPTION`] last, so it can never read as fully allowed.
pub(super) const MAX_OPTIONS: usize = 32;

/// The option name an unreadable or overflowing option reads as. It is not a
/// valid option id, so no catalog row and no stored state can match it.
const UNNAMED_OPTION: &str = "-?";

/// The state of one call: its command, refined by the options it passes once
/// the catalog lists options.
///
/// A catalog that lists options makes `root` mean a call with no options, so
/// a root call that passes any is decided by its options alone: allowed only
/// when every one is allowed. A subcommand's own state covers the options it
/// passes unless one of them is blocked. Any blocked option blocks the call,
/// and an option the catalog does not list counts as unset, so an alias or
/// abbreviation of an allowed option never rides on that allow.
pub(super) fn invocation_state(
    connection: &Connection,
    cli_id: &str,
    command_id: &str,
    options: &[String],
) -> Result<CommandState, &'static str> {
    let base = command_state(connection, cli_id, command_id)?;
    if options.is_empty() || !options_catalogued(connection, cli_id)? {
        return Ok(base);
    }
    let root = command_id == ROOT_COMMAND_ID;
    if !root && base == CommandState::Block {
        return Ok(base);
    }
    let mut every_option_allowed = true;
    for option in options {
        match command_state(connection, cli_id, option)? {
            CommandState::Block => return Ok(CommandState::Block),
            CommandState::Allow => {}
            CommandState::Inherit => every_option_allowed = false,
        }
    }
    if !root {
        return Ok(base);
    }
    Ok(if every_option_allowed {
        CommandState::Allow
    } else {
        CommandState::Inherit
    })
}

/// Whether the CLI's catalog lists any option row. A catalog from before
/// options were read lists none, and its decisions stay as they were.
fn options_catalogued(connection: &Connection, cli_id: &str) -> Result<bool, &'static str> {
    connection
        .query_row(
            "select exists(select 1 from local_cli_command where cli_id = ?1 \
             and substr(command_id, 1, 1) = '-')",
            params![cli_id],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| STORE_UNAVAILABLE)
}
