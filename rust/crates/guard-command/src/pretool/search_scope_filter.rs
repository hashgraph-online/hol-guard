//! Claude `Grep` `glob` and `type` filters, modeled on ripgrep precedence.
//!
//! ripgrep applies `--glob` overrides before ignore files: an exclusion
//! always skips, and when any inclusion exists a file is searched exactly
//! when an inclusion matches, even if an ignore file lists it. `--type`
//! narrows only files that no override or ignore rule already decided.

use super::search_scope_glob::{expand_braces, glob_matches};
use serde_json::{Map, Value};

/// Code-only type definitions from ripgrep 15.1. Data types such as `sh`
/// (which includes `.env`), `json`, or `yaml` are deliberately absent, so
/// they never narrow the modeled scope.
const CODE_TYPES: &[(&str, &[&str])] = &[
    ("c", &["*.[chH]", "*.[chH].in", "*.cats"]),
    (
        "cpp",
        &[
            "*.[ChH]",
            "*.[ChH].in",
            "*.[ch]pp",
            "*.[ch]pp.in",
            "*.[ch]xx",
            "*.[ch]xx.in",
            "*.cc",
            "*.cc.in",
            "*.hh",
            "*.hh.in",
            "*.inl",
        ],
    ),
    ("cs", &["*.cs"]),
    ("css", &["*.css", "*.scss"]),
    ("dart", &["*.dart"]),
    ("go", &["*.go"]),
    ("js", &["*.cjs", "*.js", "*.jsx", "*.mjs", "*.vue"]),
    ("kotlin", &["*.kt", "*.kts"]),
    ("lua", &["*.lua"]),
    ("py", &["*.py", "*.pyi"]),
    ("rust", &["*.rs"]),
    ("scala", &["*.sbt", "*.scala"]),
    ("svelte", &["*.svelte", "*.svelte.ts"]),
    ("swift", &["*.swift"]),
    ("ts", &["*.cts", "*.mts", "*.ts", "*.tsx"]),
    ("vue", &["*.vue"]),
    ("zig", &["*.zig"]),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Override {
    Searched,
    Skipped,
    Undecided,
}

pub(super) struct SearchFilter {
    include: Vec<String>,
    exclude: Vec<String>,
    types: &'static [&'static str],
}

impl SearchFilter {
    /// `None` means the filter cannot be modeled and no proof may be claimed.
    pub(super) fn from_input(input: &Map<String, Value>) -> Option<Self> {
        let mut filter = Self {
            include: Vec::new(),
            exclude: Vec::new(),
            types: &[],
        };
        if let Some(kind) = input.get("type") {
            let kind = kind.as_str()?;
            filter.types = CODE_TYPES
                .iter()
                .find(|(name, _)| *name == kind)
                .map_or(&[][..], |(_, globs)| *globs);
        }
        let Some(glob) = input.get("glob") else {
            return Some(filter);
        };
        let glob = glob.as_str()?;
        // Hosts may split lists on whitespace or commas; that would add
        // globs this proof did not model.
        if glob.is_empty() || glob.contains(char::is_whitespace) || has_top_level_comma(glob) {
            return None;
        }
        let (negated, body) = match glob.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, glob),
        };
        let expanded = expand_braces(body).ok()?;
        for pattern in &expanded {
            glob_matches(pattern, "probe").ok()?;
        }
        if expanded.iter().any(|pattern| pattern.contains('/')) {
            // Path-shaped globs depend on ripgrep's match base. An inclusion
            // could reach ignored files, so no proof is claimed; an
            // exclusion is dropped so it never hides a file.
            return if negated { Some(filter) } else { None };
        }
        if negated {
            filter.exclude = expanded;
        } else {
            filter.include = expanded;
        }
        Some(filter)
    }

    /// Apply glob overrides to one entry name. Directory exclusions are not
    /// modeled, so a directory is never skipped here.
    pub(super) fn override_for(&self, name: &str, is_directory: bool) -> Override {
        if !is_directory
            && self
                .exclude
                .iter()
                .any(|pattern| glob_matches(pattern, name).unwrap_or(false))
        {
            return Override::Skipped;
        }
        if self.include.is_empty() {
            return Override::Undecided;
        }
        if self
            .include
            .iter()
            .any(|pattern| glob_matches(pattern, name).unwrap_or(true))
        {
            return Override::Searched;
        }
        if is_directory {
            Override::Undecided
        } else {
            Override::Skipped
        }
    }

    pub(super) fn type_allows(&self, name: &str) -> bool {
        self.types.is_empty()
            || self
                .types
                .iter()
                .any(|pattern| glob_matches(pattern, name).unwrap_or(true))
    }
}

fn has_top_level_comma(glob: &str) -> bool {
    let mut depth = 0_i32;
    for character in glob.chars() {
        match character {
            '{' => depth += 1,
            '}' => depth -= 1,
            ',' if depth == 0 => return true,
            _ => {}
        }
    }
    false
}
