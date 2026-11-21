//! Read-only PowerShell cmdlets mapped onto the POSIX reads Guard already
//! proves.

use super::{bind, file_path, fill, path_slot, Reason, PARAMETER};
use crate::powershell_parser::PsArg;

/// Read-only and directory-creating cmdlets with a POSIX equivalent Guard
/// already proves. A form outside the bound subset keeps the cmdlet name, so it
/// is reviewed as an unknown command, as it was before these were mapped.
#[derive(Clone, Copy, PartialEq)]
pub(super) enum Benign {
    List,
    Location,
    SetLocation,
    TestPath,
    Echo,
    Search,
    Lookup,
    MakeDirectory,
    Filter,
}

pub(super) fn benign_kind(name: &str) -> Option<Benign> {
    Some(match name {
        "get-childitem" | "gci" | "dir" => Benign::List,
        "get-location" | "gl" => Benign::Location,
        "set-location" | "sl" => Benign::SetLocation,
        "test-path" => Benign::TestPath,
        "write-output" | "write-host" | "echo" => Benign::Echo,
        "select-string" | "sls" => Benign::Search,
        "get-command" | "gcm" => Benign::Lookup,
        "new-item" | "ni" => Benign::MakeDirectory,
        // Formatting cmdlets only reshape pipeline objects; none takes a path.
        // Aliases that name a native program off Windows (`sort`) stay unmapped.
        "select-object" | "select" | "sort-object" | "measure-object" | "measure"
        | "group-object" | "get-unique" | "gu" | "out-string" | "out-null" | "format-table"
        | "ft" | "format-list" | "fl" | "format-wide" | "fw" | "convertfrom-json"
        | "convertto-json" => Benign::Filter,
        _ => return None,
    })
}

pub(super) fn benign_tokens(benign: Benign, args: &[PsArg]) -> Result<Vec<String>, Reason> {
    let mut tokens = Vec::new();
    match benign {
        Benign::List => {
            let bound = bind(
                args,
                &[
                    "path",
                    "literalpath",
                    "filter",
                    "include",
                    "exclude",
                    "depth",
                ],
                &["recurse", "force", "hidden", "name", "file", "directory"],
            )?;
            let path = fill(&bound, &[&["path", "literalpath"], &["filter"]])?.remove(0);
            tokens.push("ls".to_owned());
            if bound.has("recurse") || bound.has("depth") {
                tokens.push("-R".to_owned());
            }
            if bound.has("force") || bound.has("hidden") {
                tokens.push("-a".to_owned());
            }
            if let Some(path) = path {
                tokens.push(file_path(&path)?);
            }
        }
        Benign::Location => {
            if !args.is_empty() {
                return Err(PARAMETER);
            }
            tokens.push("pwd".to_owned());
        }
        Benign::SetLocation => {
            let bound = bind(args, &["path", "literalpath"], &[])?;
            let path = path_slot(fill(&bound, &[&["path", "literalpath"]])?.remove(0))?;
            tokens.extend(["cd".to_owned(), file_path(&path)?]);
        }
        Benign::TestPath => {
            // `-IsValid` checks path syntax, not the file, so it stays unmapped.
            let bound = bind(args, &["path", "literalpath", "pathtype"], &[])?;
            let path = path_slot(fill(&bound, &[&["path", "literalpath"]])?.remove(0))?;
            let predicate = match bound.value("pathtype").map(str::to_ascii_lowercase) {
                None => "-e",
                Some(kind) if kind == "any" => "-e",
                Some(kind) if kind == "container" => "-d",
                Some(kind) if kind == "leaf" => "-f",
                Some(_) => return Err(PARAMETER),
            };
            tokens.extend(["test".to_owned(), predicate.to_owned(), file_path(&path)?]);
        }
        Benign::Echo => {
            let bound = bind(
                args,
                &[
                    "inputobject",
                    "object",
                    "foregroundcolor",
                    "backgroundcolor",
                    "separator",
                ],
                &["noenumerate", "nonewline"],
            )?;
            tokens.push("echo".to_owned());
            tokens.extend(bound.value("inputobject").map(str::to_owned));
            tokens.extend(bound.value("object").map(str::to_owned));
            tokens.extend(bound.positionals.iter().cloned());
        }
        Benign::Search => {
            let bound = bind(
                args,
                &["pattern", "path", "literalpath"],
                &[
                    "simplematch",
                    "casesensitive",
                    "list",
                    "quiet",
                    "notmatch",
                    "allmatches",
                ],
            )?;
            let mut slots = fill(&bound, &[&["pattern"], &["path", "literalpath"]])?;
            let path = slots.remove(1);
            let pattern = path_slot(slots.remove(0))?;
            tokens.push("grep".to_owned());
            for (switch, flag) in [
                ("simplematch", "-F"),
                ("list", "-l"),
                ("quiet", "-q"),
                ("notmatch", "-v"),
            ] {
                if bound.has(switch) {
                    tokens.push(flag.to_owned());
                }
            }
            if !bound.has("casesensitive") {
                tokens.push("-i".to_owned());
            }
            tokens.extend(["-e".to_owned(), pattern]);
            if let Some(path) = path {
                tokens.push(file_path(&path)?);
            }
        }
        Benign::Lookup => {
            let bound = bind(args, &["name"], &[])?;
            let name = path_slot(fill(&bound, &[&["name"]])?.remove(0))?;
            // `command` is a transparent wrapper to the parser, so the lookup
            // is modeled as `which`, which Guard already proves read-only.
            tokens.extend(["which".to_owned(), name]);
        }
        Benign::MakeDirectory => {
            let bound = bind(args, &["itemtype", "path"], &["force"])?;
            if !bound
                .value("itemtype")
                .is_some_and(|kind| kind.eq_ignore_ascii_case("directory"))
            {
                return Err(PARAMETER);
            }
            let path = path_slot(fill(&bound, &[&["path"]])?.remove(0))?;
            // New-Item creates missing parent directories, like `mkdir -p`.
            tokens.extend(["mkdir".to_owned(), "-p".to_owned(), file_path(&path)?]);
        }
        // A stdin-only filter that opens no file. `cat` would meet the
        // pipeline-read floor meant for a file that reaches another program.
        Benign::Filter => tokens.push("head".to_owned()),
    }
    Ok(tokens)
}
