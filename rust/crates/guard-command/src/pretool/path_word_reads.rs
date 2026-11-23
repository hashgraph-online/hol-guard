//! Path-word commands: the ones that rewrite or resolve a path operand.
//!
//! `dirname` and `basename` are pure string transforms. Coreutils never stats
//! the operand for either: `dirname /a/b/c` prints `/a/b` whether or not any
//! part of it exists, so the operand carries no read and the output is a
//! substring of text the caller already wrote. Neither command has an option
//! that opens, writes or executes anything, so only the option spelling and a
//! bounded single-line operand need proving.
//!
//! `readlink` and `realpath` do resolve the operand against the filesystem and
//! report whether it exists and where a symbolic link points. That is the same
//! answer `ls` gives for a path, so their operands take the same read proof an
//! `ls` operand takes, directories included. The options that take a path of
//! their own (`--relative-to`, `--relative-base`) are not admitted: they would
//! name a second location that this proof never screened.

const MAX_OPERANDS: usize = 16;

/// A path word is printed back, never opened: bounded, single-line text that
/// the shell hands over as it was written. A word carrying a command
/// substitution runs something this proof never screened before the rewrite
/// ever happens, so it is not a path word at all.
fn bounded_path_word(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.contains(['\n', '\r', '\0'])
        && crate::sfrs_path_word_lookups::path_word_runs_nothing(value)
}

/// `dirname` and `basename`, which rewrite the operand without reading it.
pub(super) fn safe_path_word_arguments(tool: &str, arguments: &[String]) -> bool {
    let mut operands = 0usize;
    let mut after_options = false;
    let mut values = arguments.iter();
    while let Some(argument) = values.next() {
        let option = argument.as_str();
        if after_options || !option.starts_with('-') || option == "-" {
            if !bounded_path_word(option) {
                return false;
            }
            operands += 1;
        } else if option == "--" {
            after_options = true;
        } else if tool == "basename" && option == "-s" {
            // The suffix is stripped from the printed name, never opened.
            if !values
                .next()
                .is_some_and(|suffix| bounded_path_word(suffix))
            {
                return false;
            }
        } else if let Some(long) = option.strip_prefix("--") {
            let allowed = match long.split_once('=') {
                Some(("suffix", suffix)) => tool == "basename" && bounded_path_word(suffix),
                Some(_) => false,
                None => long == "zero" || (tool == "basename" && long == "multiple"),
            };
            if !allowed {
                return false;
            }
        } else if !option[1..]
            .bytes()
            .all(|flag| flag == b'z' || (tool == "basename" && flag == b'a'))
        {
            return false;
        }
    }
    operands > 0 && operands <= MAX_OPERANDS
}

/// `readlink` and `realpath`, which resolve the operand and report what the
/// filesystem holds, so every operand takes the ordinary read proof.
pub(super) fn safe_resolved_path_arguments(
    tool: &str,
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let mut operands = Vec::new();
    let mut after_options = false;
    for argument in arguments {
        let option = argument.as_str();
        if after_options || !option.starts_with('-') || option == "-" {
            operands.push(option);
        } else if option == "--" {
            after_options = true;
        } else if let Some(long) = option.strip_prefix("--") {
            if long.contains('=') || !resolved_long_option(tool, long) {
                return false;
            }
        } else if !option[1..]
            .bytes()
            .all(|flag| resolved_short_flag(tool, flag))
        {
            return false;
        }
    }
    !operands.is_empty()
        && operands.len() <= MAX_OPERANDS
        && operands.iter().all(|operand| {
            super::safe_reads::command_read_target(operand, context, true)
                || package_tree_lookup(operand, context)
        })
}

/// The hidden directories a package manager writes inside a `node_modules`
/// tree: npm's and Yarn's generated launchers, and pnpm's content store with
/// the layout Bun also writes.
const PACKAGE_TREE_DIRECTORIES: [&str; 3] = [".bin", ".pnpm", ".store"];

/// Where a package manager's own shim or store entry points, for a command
/// that only prints the answer.
///
/// `realpath node_modules/.bin/tsc` answers which installed launcher a
/// project's toolchain runs, the question an agent asks before running it.
/// The ordinary read proof refuses it twice over: `node_modules/.bin` is a
/// hidden component, and the shim is a link, so under pnpm's layout the path
/// resolves through the hidden `.pnpm` store. Both refusals are about the
/// bytes of a file, and this command reads none; it prints a path.
///
/// So a lookup is proven when the spelled path and the path it resolves to
/// are both inside a `node_modules` tree, every hidden component of either is
/// one a package manager writes there, nothing above the tree is hidden, and
/// the resolved path still clears the ordinary location screen. A link that
/// leaves the tree keeps its review: the resolved path then names something
/// the package manager did not write.
fn package_tree_lookup(operand: &str, context: super::PathContext<'_>) -> bool {
    if !super::read_paths::bounded_path_spelling(operand) {
        return false;
    }
    let expanded = super::read_paths::expand_home_read_path(operand, context.home_dir)
        .unwrap_or_else(|| operand.to_owned());
    let spelled = std::path::Path::new(&expanded);
    let candidate = if spelled.is_absolute() {
        spelled.to_path_buf()
    } else {
        let Some(root) = context
            .cwd
            .filter(|root| std::path::Path::new(root).is_absolute())
        else {
            return false;
        };
        std::path::Path::new(root).join(spelled)
    };
    if !package_tree_path(&candidate) {
        return false;
    }
    std::fs::canonicalize(&candidate).is_ok_and(|canonical| {
        package_tree_path(&canonical)
            && super::read_paths::resolved_location_allowed(
                &canonical,
                context.home_dir,
                context.cwd,
                false,
            )
    })
}

/// A path inside a `node_modules` tree whose every hidden component is one a
/// package manager writes directly below a `node_modules` directory.
pub(super) fn package_tree_path(path: &std::path::Path) -> bool {
    let names: Vec<String> = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(name) => Some(name.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    let Some(root) = names.iter().position(|name| name == "node_modules") else {
        return false;
    };
    // A hidden directory above the tree is the user's own, and reading
    // through it is the question the hidden-home screens answer.
    names[..root].iter().all(|name| !name.starts_with('.'))
        && names[root..].iter().enumerate().all(|(offset, name)| {
            !name.starts_with('.')
                || (PACKAGE_TREE_DIRECTORIES.contains(&name.as_str())
                    && offset > 0
                    && names[root + offset - 1] == "node_modules")
        })
}

/// Long options that only change how the resolved path is printed.
fn resolved_long_option(tool: &str, long: &str) -> bool {
    match tool {
        "readlink" => matches!(
            long,
            "canonicalize"
                | "canonicalize-existing"
                | "canonicalize-missing"
                | "no-newline"
                | "quiet"
                | "silent"
                | "verbose"
                | "zero"
        ),
        _ => matches!(
            long,
            "canonicalize-existing"
                | "canonicalize-missing"
                | "logical"
                | "physical"
                | "quiet"
                | "strip"
                | "no-symlinks"
                | "zero"
        ),
    }
}

/// Short flags that only change how the resolved path is printed.
fn resolved_short_flag(tool: &str, flag: u8) -> bool {
    match tool {
        "readlink" => b"efmnqsvz".contains(&flag),
        _ => b"LPemqsz".contains(&flag),
    }
}
