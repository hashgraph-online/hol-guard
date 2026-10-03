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
            ) && (value.starts_with(['/', '~'])
                || value.split(['/', '\\']).any(|part| part == "..")
                || sensitive_path_argument(value)
                || glob_can_select_sensitive_path(value))
        }
        SearchValueRole::Glob | SearchValueRole::Path => {
            value.starts_with(['/', '~'])
                || value.split(['/', '\\']).any(|part| part == "..")
                || sensitive_path_argument(value)
                || glob_can_select_sensitive_path(value)
        }
        SearchValueRole::TypeGlob => value.split_once(':').is_none_or(|(_, glob)| {
            sensitive_path_argument(glob) || glob_can_select_sensitive_path(glob)
        }),
        SearchValueRole::DirectoryAction => value.eq_ignore_ascii_case("recurse"),
        SearchValueRole::Pattern | SearchValueRole::Other => false,
    }
}

pub(super) fn rg_value_role(name: &str) -> Option<SearchValueRole> {
    match name {
        "--glob" | "--iglob" => Some(SearchValueRole::Glob),
        "--regexp" => Some(SearchValueRole::Pattern),
        "--file" | "--ignore-file" => Some(SearchValueRole::Path),
        "--type-add" => Some(SearchValueRole::TypeGlob),
        "--after-context"
        | "--before-context"
        | "--context"
        | "--encoding"
        | "--engine"
        | "--max-columns"
        | "--max-count"
        | "--max-depth"
        | "--threads"
        | "--type"
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
