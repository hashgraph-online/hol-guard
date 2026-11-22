//! Reading a property list with `plutil`.
//!
//! `plutil -p Info.plist` prints a plist whatever format it is stored in, and
//! `plutil -lint` reports whether one parses. Both answer a question about a
//! file the caller named and write nothing. `-extract` and `-type` read one
//! value out of the same file and print it.
//!
//! The same program rewrites those files, so the first argument decides.
//! `-convert` writes the file back in another format, `-insert`, `-replace`
//! and `-remove` change its contents, and `-create` makes a new one. None of
//! them is read this way, and a first argument this screen does not know
//! leaves the command under review rather than being taken for a read.
//!
//! `-o` names where the result is written, so it is admitted only as `-o -`,
//! which is standard output. The files go through the same bounded,
//! sensitive-path-aware read proof `cat` uses. A `-` operand reads standard
//! input, whose contents nothing here can see, and keeps its review.

use super::safe_reads::command_read_target;

const MAX_FILES: usize = 16;

/// The plist formats `-extract` can print a value as.
const FORMATS: &[&str] = &["xml1", "binary1", "json", "raw"];

/// The types `-expect` compares the value at a key path against.
const EXPECT_TYPES: &[&str] = &[
    "bool", "integer", "float", "string", "date", "data", "array", "dict",
];

/// A key path names a place inside the document, never a file.
fn key_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

struct Call<'a> {
    files: Vec<&'a str>,
}

/// Read the call, or decline it when any part of it is not a reading.
fn call(arguments: &[String]) -> Option<Call<'_>> {
    let (verb, rest) = arguments.split_first()?;
    let mut remaining = rest;
    match verb.as_str() {
        "-p" | "-lint" => {}
        "-extract" => {
            let (path, tail) = remaining.split_first()?;
            let (format, tail) = tail.split_first()?;
            if !key_path(path) || !FORMATS.contains(&format.as_str()) {
                return None;
            }
            remaining = tail;
        }
        "-type" => {
            let (path, tail) = remaining.split_first()?;
            if !key_path(path) {
                return None;
            }
            remaining = tail;
        }
        _ => return None,
    }

    let mut files = Vec::new();
    let mut operands_only = false;
    while let Some((word, tail)) = remaining.split_first() {
        remaining = tail;
        if operands_only {
            files.push(word.as_str());
            continue;
        }
        match word.as_str() {
            "--" => operands_only = true,
            "-s" | "-r" | "-n" => {}
            "-expect" => {
                let (value, next) = remaining.split_first()?;
                if !EXPECT_TYPES.contains(&value.as_str()) {
                    return None;
                }
                remaining = next;
            }
            "-o" => {
                let (value, next) = remaining.split_first()?;
                if value != "-" {
                    return None;
                }
                remaining = next;
            }
            other if other.starts_with('-') => return None,
            other => files.push(other),
        }
    }

    (!files.is_empty() && files.len() <= MAX_FILES).then_some(Call { files })
}

/// `plutil` asking a question about the files it was given.
pub(super) fn safe_property_list_read(
    basename: &str,
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    basename == "plutil"
        && call(arguments).is_some_and(|call| {
            call.files
                .iter()
                .all(|file| command_read_target(file, context, false))
        })
}

#[cfg(test)]
#[path = "property_list_reads_tests.rs"]
mod tests;
