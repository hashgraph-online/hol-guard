//! Oh My Pi JSON query reads: `file.json?q=<filter>`.
//!
//! Oh My Pi splits a `read` path at its first `?` when the text before it
//! names a `.json`, `.jsonl` or `.ndjson` file, then runs `jq` with the
//! filter over that file. The filter can only select and reshape the file's
//! own values, except for the builtins that reach outside it (`env`, `$ENV`,
//! `input_filename`, modules, `input`), so the proof accepts a small filter
//! grammar whose every bare word is a known pure builtin. Generators that run
//! without bound, definitions, variables, string interpolation and format
//! strings are left for review. The query reads no more than the bare file,
//! so the file itself still needs the ordinary read proof.

const MAX_FILTER_BYTES: usize = 512;

/// Pure builtins and keywords a filter may name. Each reads only its input.
const FILTER_WORDS: &[&str] = &[
    "add",
    "all",
    "and",
    "any",
    "arrays",
    "ascii_downcase",
    "ascii_upcase",
    "booleans",
    "contains",
    "del",
    "elif",
    "else",
    "empty",
    "end",
    "endswith",
    "false",
    "first",
    "flatten",
    "from_entries",
    "group_by",
    "has",
    "if",
    "index",
    "join",
    "keys",
    "keys_unsorted",
    "last",
    "length",
    "ltrimstr",
    "map",
    "map_values",
    "max",
    "max_by",
    "min",
    "min_by",
    "not",
    "null",
    "nulls",
    "numbers",
    "objects",
    "or",
    "paths",
    "reverse",
    "rtrimstr",
    "select",
    "sort",
    "sort_by",
    "split",
    "startswith",
    "strings",
    "then",
    "to_entries",
    "tojson",
    "tostring",
    "tonumber",
    "true",
    "type",
    "unique",
    "unique_by",
    "values",
    "with_entries",
];

/// The JSON file a `file.json?q=<filter>` read queries, when the query
/// string holds only Oh My Pi's options and a filter in the bounded grammar.
pub(super) fn json_query_base(value: &str) -> Option<&str> {
    let (base, query) = value.split_once('?')?;
    let lowered = base.to_ascii_lowercase();
    if !(lowered.ends_with(".json") || lowered.ends_with(".jsonl") || lowered.ends_with(".ndjson"))
    {
        return None;
    }
    // A `:` would let the host peel a line selector off the whole string
    // before splitting the query, so it is left for review.
    if base.contains(':') || query.contains([':', '%', '#']) {
        return None;
    }
    let mut filter = None;
    for parameter in query.split('&') {
        let (key, value) = parameter.split_once('=')?;
        match key {
            "q" | "query" if filter.is_none() && !value.is_empty() => filter = Some(value),
            "raw" | "compact" if matches!(value, "true" | "false" | "1" | "0") => {}
            "offset" | "limit" if !value.is_empty() && value.len() <= 6 => {
                if !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return None;
                }
            }
            _ => return None,
        }
    }
    bounded_filter(filter?).then_some(base)
}

fn bounded_filter(filter: &str) -> bool {
    if filter.len() > MAX_FILTER_BYTES || filter.trim().is_empty() {
        return false;
    }
    let bytes = filter.as_bytes();
    let mut index = 0;
    let mut field_access = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'"' {
            // Plain string literals only: an escape could open `\(...)`
            // interpolation, which runs a nested filter.
            let Some(length) = filter[index + 1..].find('"') else {
                return false;
            };
            if filter[index + 1..index + 1 + length].contains(['\\', '\n', '\r']) {
                return false;
            }
            index += length + 2;
            field_access = false;
            continue;
        }
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            // `.name` is a field of the input, not a builtin.
            if !field_access && !FILTER_WORDS.contains(&&filter[start..index]) {
                return false;
            }
            field_access = false;
            continue;
        }
        if !(byte.is_ascii_digit()
            || matches!(
                byte,
                b' ' | b'.'
                    | b'['
                    | b']'
                    | b'{'
                    | b'}'
                    | b'('
                    | b')'
                    | b'|'
                    | b','
                    | b'='
                    | b'!'
                    | b'<'
                    | b'>'
                    | b'+'
                    | b'-'
                    | b'*'
                    | b'/'
                    | b'?'
            ))
        {
            return false;
        }
        field_access = byte == b'.';
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::json_query_base;

    #[test]
    fn plain_filters_name_the_queried_file() {
        for (value, base) in [
            (
                "scripts/queries.json?q=.queries.auth_outcomes",
                "scripts/queries.json",
            ),
            (
                "/w/data.JSONL?q=.items[] | select(.ok == true) | .name&raw=true",
                "/w/data.JSONL",
            ),
            (
                "a.ndjson?query=keys&compact=1&offset=10&limit=20",
                "a.ndjson",
            ),
            ("a.json?q=.a // \"none\"", "a.json"),
            ("a.json?q=[.[] | .name] | length", "a.json"),
            ("a.json?q=to_entries | map(select(.value > 2))", "a.json"),
        ] {
            assert_eq!(json_query_base(value), Some(base), "{value}");
        }
    }

    #[test]
    fn filters_that_reach_past_the_file_stay_unproven() {
        for value in [
            "a.json?q=env",
            "a.json?q=$ENV.HOME",
            "a.json?q=.a | env.TOKEN",
            "a.json?q=input_filename",
            "a.json?q=input",
            "a.json?q=import \"x\" as x; .",
            "a.json?q=include \"x\"; .",
            "a.json?q=def f: .; f",
            "a.json?q=\"\\(env)\"",
            "a.json?q=@sh",
            "a.json?q=range(100000000)",
            "a.json?q=repeat(.)",
            "a.json?q=.a %25 2",
            "a.json?q=.a # comment",
            "a.json?q=.a&q=.b",
            "a.json?q=",
            "a.json?q=.a&format=raw",
            "a.json?q=.a&limit=-1",
            "a.json?q={a: .b}",
            "a.json?q={name, id}",
            "a.json:1-5?q=.a",
            "a.txt?q=.a",
            "a.json",
        ] {
            assert_eq!(json_query_base(value), None, "{value}");
        }
    }
}
