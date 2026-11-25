//! A `*_PATH` setting that names one data file the command reads or writes.
//!
//! `PATH` is a code-loading marker because a search path decides where a
//! program, its loader or its interpreter finds code (`NODE_PATH`,
//! `GIT_EXEC_PATH`, `C_INCLUDE_PATH`), and a directory such as a source tree
//! handed to a test harness is code too. A name such as `REPORT_LEDGER_PATH`
//! carrying `out/ledger.jsonl` names a data file instead. Refusing it left the
//! command no reviewable form at all: the extension controls could not
//! evaluate it, so the run was blocked with nothing to approve, while the same
//! value under `REPORT_LEDGER_FILE` reached the ordinary decision.
//!
//! The name alone cannot tell the two apart, so the value decides. It must be
//! one plain file path ending in a data extension, with no list separator,
//! expansion, glob or option, so it names neither a directory to search nor a
//! list of them. The rest of the name must carry no other code-loading,
//! redirect, credential, trust-anchor or endpoint marker. A search-path family
//! that reads a single entry as a file of code stays refused by its stem:
//! `LUA_PATH` holds templates, so `LUA_PATH=x.json` loads `x.json` as Lua.

use super::environment::{
    code_or_redirect_environment_name, credential_routing_environment_name,
    endpoint_steering_environment_name, trust_anchor_environment_name,
};

/// Extensions of files that hold records, tables or logs rather than code or
/// configuration.
const DATA_EXTENSIONS: &[&str] = &["csv", "json", "jsonl", "log", "ndjson", "tsv", "txt"];

/// Stems of search-path settings a language runtime or package manager reads,
/// where an entry may be a template or an archive of code rather than a
/// directory.
const SEARCH_PATH_STEMS: &[&str] = &[
    "BUNDLE",
    "GEM",
    "GUILE_LOAD",
    "GUILE_LOAD_COMPILED",
    "JULIA_DEPOT",
    "LUA",
    "NODE",
    "PERL",
    "PERL5",
    "PYTHON",
    "RUBY",
    "SASS",
];

const MAX_VALUE_CHARS: usize = 1024;

/// Whether `name=value` is a `*_PATH` setting naming one data file.
pub(crate) fn data_file_path_setting(name: &str, value: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let Some(stem) = upper.strip_suffix("_PATH") else {
        return false;
    };
    !stem.is_empty()
        && upper
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !stem.contains("PATH")
        && !stem.contains("INCLUDE")
        && !SEARCH_PATH_STEMS.contains(&stem)
        && !code_or_redirect_environment_name(stem)
        && !credential_routing_environment_name(&upper)
        && !trust_anchor_environment_name(&upper)
        && !endpoint_steering_environment_name(&upper)
        && data_file_value(value)
}

/// One plain file path whose last component ends in a data extension.
fn data_file_value(value: &str) -> bool {
    let body = value.strip_prefix("~/").unwrap_or(value);
    if value.is_empty()
        || value.len() > MAX_VALUE_CHARS
        || value.starts_with('-')
        || !body.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'+' | b'@')
        })
    {
        return false;
    }
    let Some(file) = body.rsplit('/').next() else {
        return false;
    };
    let Some((head, extension)) = file.rsplit_once('.') else {
        return false;
    };
    !head.is_empty()
        && !head.chars().all(|character| character == '.')
        && DATA_EXTENSIONS
            .iter()
            .any(|known| extension.eq_ignore_ascii_case(known))
}

#[cfg(test)]
mod tests {
    use super::data_file_path_setting;

    #[test]
    fn only_a_single_data_file_under_an_unclaimed_name_passes() {
        for (name, value) in [
            ("REPORT_LEDGER_PATH", "out/ledger.jsonl"),
            ("REPORT_LEDGER_PATH", "/srv/evidence/ledger.jsonl"),
            ("report_ledger_path", "~/evidence/ledger.ndjson"),
            ("SUMMARY_PATH", "build/summary.JSON"),
            ("RESULTS_PATH", "results.csv"),
        ] {
            assert!(data_file_path_setting(name, value), "{name}={value}");
        }
        for (name, value) in [
            ("REPORT_LEDGER_PATH", "out"),
            ("REPORT_LEDGER_PATH", "a.jsonl:b.jsonl"),
            ("REPORT_LEDGER_PATH", "a.jsonl,b.jsonl"),
            ("REPORT_LEDGER_PATH", "run.sh"),
            ("REPORT_LEDGER_PATH", "out/*.jsonl"),
            ("REPORT_LEDGER_PATH", "$HOME/a.jsonl"),
            ("REPORT_LEDGER_PATH", "-x.jsonl"),
            ("REPORT_LEDGER_PATH", ".jsonl"),
            ("REPORT_LEDGER_PATH", "out/..json"),
            ("REPORT_LEDGER_PATH", ""),
            ("PATH", "a.json"),
            ("_PATH", "a.json"),
            ("PYTHONPATH", "a.json"),
            ("NODE_PATH", "a.json"),
            ("LUA_PATH", "a.json"),
            ("GEM_PATH", "a.json"),
            ("C_INCLUDE_PATH", "a.json"),
            ("LD_LIBRARY_PATH", "a.json"),
            ("GIT_EXEC_PATH", "a.json"),
            ("REPORT_PLUGIN_PATH", "a.json"),
            ("REPORT_CONFIG_PATH", "a.json"),
            ("REPORT_HOME_PATH", "a.json"),
            ("REPORT_TOKEN_PATH", "a.json"),
            ("REPORT_CERT_PATH", "a.json"),
            ("REPORT_URL_PATH", "a.json"),
            ("REPORT_PATH_PATH", "a.json"),
            ("REPORT-LEDGER_PATH", "a.json"),
        ] {
            assert!(!data_file_path_setting(name, value), "{name}={value}");
        }
    }
}
