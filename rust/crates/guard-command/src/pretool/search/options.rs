use super::{
    glob_can_select_sensitive_path, literal_glob_names_sensitive_path, sensitive_path_argument,
    ReadContext, SearchValueRole,
};

pub(super) fn unsafe_search_value(
    role: SearchValueRole,
    value: &str,
    context: ReadContext<'_>,
) -> bool {
    match role {
        SearchValueRole::Path
            if (context.home_dir.is_some() || context.cwd.is_some())
                && !value.contains(['*', '?', '[', ']', '{', '}']) =>
        {
            // Recursive searchers walk directories; only prove regular files canonically.
            !super::super::safe_reads::bounded_read_target(
                value,
                context.home_dir,
                context.cwd,
                false,
            ) && !super::super::chain_temporary::absent_temporary_read_target(
                value,
                context.home_dir,
                context.cwd,
            ) && !super::super::read_paths::home_hidden_content_read(
                value,
                context.home_dir,
                context.cwd,
            ) && (rooted_operand(value)
                || value.split(['/', '\\']).any(|part| part == "..")
                || sensitive_path_argument(value)
                || glob_can_select_sensitive_path(value)
                || link_reaches_outside(value, context))
        }
        SearchValueRole::RgGlob if value.starts_with('!') => false,
        SearchValueRole::Glob | SearchValueRole::RgGlob | SearchValueRole::Path => {
            rooted_operand(value)
                || value.split(['/', '\\']).any(|part| part == "..")
                || sensitive_path_argument(value)
                || glob_can_select_sensitive_path(value)
                || (matches!(role, SearchValueRole::Path) && glob_reaches_outside(value, context))
        }
        // `name:include:other` copies another type's globs unscreened.
        SearchValueRole::TypeGlob => value.split_once(':').is_none_or(|(_, glob)| {
            glob.starts_with("include:")
                || sensitive_path_argument(glob)
                || glob_can_select_sensitive_path(glob)
        }),
        SearchValueRole::RgType => !SOURCE_TYPES.contains(&value),
        SearchValueRole::DirectoryAction => value.eq_ignore_ascii_case("recurse"),
        // A pattern matches the text a stage is handed, so an ordinary word
        // there names no file. The shell reaches it first: `.env{,.local}`
        // leaves `.env` as the pattern and `.env.local` as an operand the
        // stage then opens, and `.env*` becomes one as soon as a second name
        // is beside it. A pattern whose expansions can select a credential
        // path is therefore not a pattern yet.
        //
        // Only the glob's own text answers that question. A regex carries
        // `.*` wherever it joins two words, and asking whether some string
        // the glob could match would start with or hold a credential marker
        // says yes to every one of them: `rg 'Delegate\b.*=>' src` and
        // `rg 'Auth.*Provider' src` are searches, not file names.
        //
        // A pattern whose glob characters are all quoted is past the shell
        // already: `grep -o "FAILED tests/[^ ]*" log` hands `grep` that text
        // and no file name, whatever files sit in the directory.
        SearchValueRole::Pattern => {
            !quoted_pattern(context.literal_words, value)
                && literal_glob_names_sensitive_path(value)
        }
        SearchValueRole::Other => false,
    }
}

/// Whether a relative operand passes through a link whose target lies
/// outside the working folder or fails the name screens there. The fallback
/// above judges a relative operand by its spelling, so a checkout that
/// carries `src/link.ts -> ~/notes/secret.txt` must not be read by its
/// in-repo name. A link that stays inside the folder reads like its target.
fn link_reaches_outside(value: &str, context: ReadContext<'_>) -> bool {
    let Some(cwd) = context.cwd else {
        return false;
    };
    let cwd = std::path::Path::new(cwd);
    let mut walked = cwd.to_path_buf();
    let mut linked = false;
    for part in std::path::Path::new(value).components() {
        walked.push(part);
        linked |= std::fs::symlink_metadata(&walked)
            .is_ok_and(|metadata| metadata.file_type().is_symlink());
    }
    if !linked {
        return false;
    }
    link_target_unsafe(&walked, cwd)
}

/// Whether the file a link reaches lies outside `cwd` or fails the name
/// screens below it.
fn link_target_unsafe(link: &std::path::Path, cwd: &std::path::Path) -> bool {
    let (Ok(target), Ok(root)) = (std::fs::canonicalize(link), std::fs::canonicalize(cwd)) else {
        return true;
    };
    let Ok(relative) = target.strip_prefix(&root) else {
        return true;
    };
    guard_secure_fs::sensitive_path_family(&target).is_some()
        || guard_secure_fs::credential_named_path(relative)
        || sensitive_path_argument(&relative.to_string_lossy())
}

/// Entries the walk below reads before it gives up.
const MAX_LINK_WALK: usize = 10_000;

/// Whether a relative glob could select a link that [`link_target_unsafe`]
/// turns down. The walk starts at the glob's literal prefix and goes as deep
/// as the glob does (any depth for `**`). It counts every link it meets,
/// whatever the glob would select, and a walk that runs out of room or
/// cannot read a directory counts as meeting one.
fn glob_reaches_outside(value: &str, context: ReadContext<'_>) -> bool {
    context
        .cwd
        .is_some_and(|cwd| glob_meets_unsafe_link(value, std::path::Path::new(cwd)))
}

fn glob_meets_unsafe_link(value: &str, cwd: &std::path::Path) -> bool {
    const GLOB: [char; 6] = ['*', '?', '[', ']', '{', '}'];
    if !value.contains(GLOB) {
        return false;
    }
    let parts: Vec<&str> = value.split('/').filter(|part| !part.is_empty()).collect();
    let literal = parts.iter().take_while(|part| !part.contains(GLOB)).count();
    let mut directory = cwd.to_path_buf();
    for part in &parts[..literal] {
        directory.push(part);
        if std::fs::symlink_metadata(&directory)
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
            && link_target_unsafe(&directory, cwd)
        {
            return true;
        }
    }
    if !directory.is_dir() {
        return false;
    }
    let remaining = &parts[literal..];
    let depth = if remaining.iter().any(|part| part.contains("**")) {
        usize::MAX
    } else {
        remaining.len()
    };
    // The shell's glob descends through a link to a directory, so the walk
    // does too, once per real directory a link reaches.
    let mut linked = std::collections::HashSet::new();
    linked.extend(std::fs::canonicalize(&directory));
    let mut pending = vec![(directory, 1usize)];
    let mut seen = 0usize;
    while let Some((directory, level)) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            return true;
        };
        for entry in entries {
            seen += 1;
            let Ok(entry) = entry else {
                return true;
            };
            let Ok(kind) = entry.file_type() else {
                return true;
            };
            if seen > MAX_LINK_WALK {
                return true;
            }
            if kind.is_symlink() {
                let path = entry.path();
                if link_target_unsafe(&path, cwd) {
                    return true;
                }
                if level < depth && path.is_dir() {
                    let Ok(real) = std::fs::canonicalize(&path) else {
                        return true;
                    };
                    if linked.insert(real) {
                        pending.push((path, level + 1));
                    }
                }
            } else if kind.is_dir() && level < depth {
                pending.push((entry.path(), level + 1));
            }
        }
    }
    false
}

/// Whether `value` reaches the program in a word whose glob characters are
/// all quoted: on its own (`-e 's[a-z]*'`) or attached to its option
/// (`-e"s[a-z]*"`, `--regexp="s[a-z]*"`), where the option reader hands over
/// only the part after the option.
fn quoted_pattern(literal_words: &[String], value: &str) -> bool {
    literal_words.iter().any(|word| {
        word == value
            || word.strip_suffix(value).is_some_and(|option| {
                option.starts_with('-') && (option.ends_with('=') || !option.starts_with("--"))
            })
    })
}

/// A home, root, drive or UNC spelling names a place outside the working
/// directory, so it never gets the relative-path floor. Windows accepts
/// `C:\work`, `C:/work` and `\\server\share` as well as `/work`.
fn rooted_operand(value: &str) -> bool {
    value.starts_with('~') || super::super::read_paths::rooted(value)
}

/// `rg` file types whose built-in globs name only source and data
/// extensions or ordinary build files. A selected type's globs also select
/// hidden files, and some types name dotfiles outright: `sh` includes
/// `.env` and `.bashrc`, so only these names are proven. A `--type-add`
/// for one of them adds globs that pass the `TypeGlob` screen first.
const SOURCE_TYPES: &[&str] = &[
    "c",
    "cmake",
    "cpp",
    "cs",
    "csharp",
    "css",
    "dart",
    "elixir",
    "erlang",
    "go",
    "graphql",
    "groovy",
    "h",
    "haskell",
    "hs",
    "html",
    "java",
    "js",
    "json",
    "jsonl",
    "kotlin",
    "lua",
    "make",
    "markdown",
    "md",
    "nix",
    "ocaml",
    "perl",
    "php",
    "protobuf",
    "py",
    "python",
    "rust",
    "scala",
    "sql",
    "svelte",
    "swift",
    "toml",
    "ts",
    "txt",
    "typescript",
    "vue",
    "xml",
    "yaml",
    "zig",
];

pub(super) fn rg_value_role(name: &str) -> Option<SearchValueRole> {
    match name {
        "--glob" | "--iglob" => Some(SearchValueRole::RgGlob),
        "--regexp" => Some(SearchValueRole::Pattern),
        // An ignore file's `!` rules re-include hidden files, so
        // `--ignore-file` stays unproved like `--no-ignore`.
        "--file" => Some(SearchValueRole::Path),
        "--type-add" => Some(SearchValueRole::TypeGlob),
        "--type" => Some(SearchValueRole::RgType),
        "--after-context"
        | "--before-context"
        | "--context"
        | "--encoding"
        | "--engine"
        | "--max-columns"
        | "--max-count"
        | "--max-depth"
        | "--threads"
        | "--type-clear"
        | "--type-not"
        | "--color"
        | "--colors"
        | "--context-separator"
        | "--dfa-size-limit"
        | "--field-context-separator"
        | "--field-match-separator"
        | "--path-separator"
        | "--regex-size-limit"
        | "--replace"
        | "--sort"
        | "--sortr" => Some(SearchValueRole::Other),
        _ => None,
    }
}

pub(super) fn grep_value_role(name: &str) -> Option<SearchValueRole> {
    match name {
        "--regexp" => Some(SearchValueRole::Pattern),
        "--include" => Some(SearchValueRole::Glob),
        "--directories" => Some(SearchValueRole::DirectoryAction),
        "--after-context" | "--before-context" | "--context" | "--max-count" | "--binary-files"
        | "--color" | "--colour" | "--devices" | "--exclude" | "--exclude-dir"
        | "--group-separator" | "--label" => Some(SearchValueRole::Other),
        _ => None,
    }
}

pub(super) fn safe_rg_flag(name: &str) -> bool {
    matches!(
        name,
        "--binary"
            | "--block-buffered"
            | "--byte-offset"
            | "--case-sensitive"
            | "--column"
            | "--count"
            | "--count-matches"
            | "--crlf"
            | "--debug"
            | "--files"
            | "--files-with-matches"
            | "--files-without-match"
            | "--fixed-strings"
            | "--heading"
            | "--help"
            | "--ignore-case"
            | "--include-zero"
            | "--invert-match"
            | "--json"
            | "--line-buffered"
            | "--line-number"
            | "--no-config"
            | "--no-filename"
            | "--no-heading"
            | "--no-line-number"
            | "--no-messages"
            | "--no-pcre2-unicode"
            | "--no-require-git"
            | "--no-unicode"
            | "--null"
            | "--null-data"
            | "--one-file-system"
            | "--only-matching"
            | "--passthru"
            | "--pcre2"
            | "--pcre2-version"
            | "--pretty"
            | "--quiet"
            // Runs gzip, xz and the like from PATH, as PATH already chose
            // rg itself, only to decompress files the scope checks admitted.
            // ripgrep 13 stopped resolving them from the cwd on Windows.
            | "--search-zip"
            | "--smart-case"
            | "--stats"
            | "--stop-on-nonmatch"
            | "--text"
            | "--trace"
            | "--trim"
            | "--type-list"
            | "--unicode"
            | "--version"
            | "--vimgrep"
            | "--with-filename"
            | "--word-regexp"
    )
}

pub(super) fn safe_grep_flag(name: &str) -> bool {
    matches!(
        name,
        "--byte-offset"
            | "--count"
            | "--extended-regexp"
            | "--fixed-strings"
            | "--help"
            | "--ignore-case"
            | "--initial-tab"
            | "--invert-match"
            | "--line-buffered"
            | "--line-number"
            | "--line-regexp"
            | "--no-filename"
            | "--no-group-separator"
            | "--no-messages"
            | "--null"
            | "--null-data"
            | "--only-matching"
            | "--perl-regexp"
            | "--quiet"
            | "--silent"
            | "--text"
            | "--version"
            | "--with-filename"
            | "--word-regexp"
    )
}

#[cfg(all(test, unix))]
#[path = "options_link_tests.rs"]
mod link_tests;
