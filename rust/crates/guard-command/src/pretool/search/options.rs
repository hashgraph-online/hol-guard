use super::{
    glob_can_select_sensitive_path, sensitive_path_argument, ReadContext, SearchValueRole,
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
                || glob_can_select_sensitive_path(value))
        }
        SearchValueRole::RgGlob if value.starts_with('!') => false,
        SearchValueRole::Glob | SearchValueRole::RgGlob | SearchValueRole::Path => {
            rooted_operand(value)
                || value.split(['/', '\\']).any(|part| part == "..")
                || sensitive_path_argument(value)
                || glob_can_select_sensitive_path(value)
        }
        // `name:include:other` copies another type's globs unscreened.
        SearchValueRole::TypeGlob => value.split_once(':').is_none_or(|(_, glob)| {
            glob.starts_with("include:")
                || sensitive_path_argument(glob)
                || glob_can_select_sensitive_path(glob)
        }),
        SearchValueRole::RgType => !SOURCE_TYPES.contains(&value),
        SearchValueRole::DirectoryAction => value.eq_ignore_ascii_case("recurse"),
        SearchValueRole::Pattern | SearchValueRole::Other => false,
    }
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
