//! The options a local CLI call passes, and how they refine its grant.

use std::collections::BTreeSet;

use rusqlite::{params, Connection};

use super::{command_state, CommandState, OTHER_COMMAND_ID, ROOT_COMMAND_ID, STORE_UNAVAILABLE};

/// The option names an invocation passes, from the arguments after its
/// runner or script path: every argument that starts with `-`, cut at `=`.
/// A bare `--` is skipped, not read as the end of options: many scripts
/// never treat it that way, so an option after it still reaches them.
/// `--help` and `--version` are skipped because no catalog lists them. A
/// spelling no catalog can hold, or a call past `MAX_OPTIONS`, reads as
/// [`UNNAMED_OPTION`], which no catalog row matches.
pub(crate) fn invocation_options(arguments: &[String]) -> Vec<String> {
    let mut options: Vec<String> = Vec::new();
    for argument in arguments {
        if argument == "-" || argument == "--" || !argument.starts_with('-') {
            continue;
        }
        let name = argument.split('=').next().unwrap_or_default();
        if matches!(name, "--help" | "--version") {
            continue;
        }
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

/// What a call passes besides its command: the catalogued commands it names
/// after its first option, then [`invocation_options`], within `MAX_OPTIONS`.
///
/// The command-name tokens stop at the first option, so `tool --verbose
/// deploy` resolves to the root. Reading `deploy` here keeps an allowed
/// option from carrying a command it comes before. An argument that only
/// looks like a command, such as an option's value, can make the call
/// stricter but never looser.
pub(crate) fn invocation_entries(
    arguments: &[String],
    command_id: &str,
    catalog: &BTreeSet<String>,
) -> Vec<String> {
    let mut entries: Vec<String> = Vec::new();
    let start = arguments
        .iter()
        .position(|argument| argument.starts_with('-') && argument != "-");
    for argument in start.map_or(&[][..], |start| &arguments[start..]) {
        if argument.starts_with('-') {
            continue;
        }
        for candidate in [argument.clone(), format!("{command_id}.{argument}")] {
            let named = candidate != command_id
                && candidate != ROOT_COMMAND_ID
                && candidate != OTHER_COMMAND_ID
                && catalog.contains(&candidate);
            if named && !entries.contains(&candidate) && entries.len() < MAX_LATER_COMMANDS {
                entries.push(candidate);
            }
        }
    }
    let mut options = invocation_options(arguments);
    let room = MAX_OPTIONS - entries.len();
    if options.len() > room {
        options.truncate(room - 1);
        options.push(UNNAMED_OPTION.to_owned());
    }
    entries.extend(options);
    entries
}

/// Most option names one request carries. A longer call is cut short with
/// [`UNNAMED_OPTION`] last, so it can never read as fully allowed.
pub(super) const MAX_OPTIONS: usize = 32;

/// Most commands [`invocation_entries`] reads after a call's first option.
const MAX_LATER_COMMANDS: usize = 8;

/// The option name an unreadable or overflowing option reads as. It is not a
/// valid option id, so no catalog row and no stored state can match it.
const UNNAMED_OPTION: &str = "-?";

/// The state of one call: its command, refined by what else it passes.
///
/// `entries` holds the call's options and any catalogued command it names
/// after an option (see [`invocation_entries`]). Any blocked entry blocks
/// the call, and a blocked subcommand stays blocked. A later command that is
/// not allowed leaves the call to review.
///
/// Options count once the catalog lists them. A root call whose options are
/// all allowed is allowed, even when the root row itself is not. Otherwise
/// the command's own state decides, with one exception: while any option is
/// blocked, an unset or unlisted option does not ride on an allowed command.
/// It could be an alias, abbreviation or bundle of the blocked one (`-f`,
/// `--forc`, `-fv`), so the call goes to review.
pub(super) fn invocation_state(
    connection: &Connection,
    cli_id: &str,
    command_id: &str,
    entries: &[String],
) -> Result<CommandState, &'static str> {
    let base = command_state(connection, cli_id, command_id)?;
    if entries.is_empty() {
        return Ok(base);
    }
    let root = command_id == ROOT_COMMAND_ID;
    if !root && base == CommandState::Block {
        return Ok(base);
    }
    let catalogued = options_catalogued(connection, cli_id)?;
    let mut later_command_unset = false;
    let mut option_passed = false;
    let mut every_option_allowed = true;
    for entry in entries {
        let option = entry.starts_with('-');
        if option && !catalogued {
            continue;
        }
        option_passed |= option;
        match command_state(connection, cli_id, entry)? {
            CommandState::Block => return Ok(CommandState::Block),
            CommandState::Allow => {}
            CommandState::Inherit if option => every_option_allowed = false,
            CommandState::Inherit => later_command_unset = true,
        }
    }
    if later_command_unset {
        return Ok(if base == CommandState::Block {
            base
        } else {
            CommandState::Inherit
        });
    }
    if !option_passed {
        return Ok(base);
    }
    if every_option_allowed {
        return Ok(if root { CommandState::Allow } else { base });
    }
    if base == CommandState::Allow && option_blocked(connection, cli_id)? {
        return Ok(CommandState::Inherit);
    }
    Ok(base)
}

/// Whether `entries` hold an option the catalog's option rows decide, so a
/// call that passes one is not covered by a package script's own surface.
pub(super) fn options_decide(
    connection: &Connection,
    cli_id: &str,
    entries: &[String],
) -> Result<bool, &'static str> {
    Ok(entries.iter().any(|entry| entry.starts_with('-'))
        && options_catalogued(connection, cli_id)?)
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

/// Whether the operator blocked any of the CLI's options.
fn option_blocked(connection: &Connection, cli_id: &str) -> Result<bool, &'static str> {
    connection
        .query_row(
            "select exists(select 1 from local_cli_command_grant where cli_id = ?1 \
             and substr(command_id, 1, 1) = '-' and state = 'block')",
            params![cli_id],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| STORE_UNAVAILABLE)
}
