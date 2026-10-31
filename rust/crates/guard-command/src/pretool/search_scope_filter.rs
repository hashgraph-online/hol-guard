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
    /// An inclusion that holds a `/` matches the path a walk reaches an
    /// entry by, not its name, so the walk must offer that path.
    path_shaped: bool,
}

impl SearchFilter {
    /// `None` means the filter cannot be modeled and no proof may be claimed.
    pub(super) fn from_input(input: &Map<String, Value>) -> Option<Self> {
        let mut filter = Self {
            include: Vec::new(),
            exclude: Vec::new(),
            types: &[],
            path_shaped: false,
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

    /// The inclusions of shell `rg -g` options. A shell passes each glob
    /// whole. A glob that holds a `/` matches against the path from the
    /// search root, so it is modeled against that path; a glob without one
    /// matches a name at any depth. An inclusion overrides both the hidden
    /// and the ignore rules, so a glob that could select `.git` is modeled
    /// only when the walk can offer `.git` the same match.
    pub(super) fn from_rg_inclusions(globs: &[&str]) -> Option<Self> {
        let mut include = Vec::new();
        let mut path_shaped = false;
        for glob in globs {
            if glob.starts_with('!') || glob.contains('\\') {
                return None;
            }
            for pattern in expand_braces(glob).ok()? {
                // A rooted glob, a directory glob and one that climbs out
                // each match against a base this walk does not model.
                if pattern.starts_with('/')
                    || pattern.ends_with('/')
                    || pattern.contains("//")
                    || pattern.split('/').any(|component| component == "..")
                {
                    return None;
                }
                // Reject a pattern the bounded matcher cannot evaluate.
                glob_matches(&pattern, "probe").ok()?;
                path_shaped |= pattern.contains('/');
                include.push(pattern);
            }
        }
        if !path_shaped
            && include
                .iter()
                .any(|pattern| glob_matches(pattern, ".git").unwrap_or(true))
        {
            // Without a path to match, the walk cannot model which `.git`
            // such a glob reaches, and it always skips that directory.
            return None;
        }
        (!include.is_empty()).then_some(Self {
            include,
            exclude: Vec::new(),
            types: &[],
            path_shaped,
        })
    }

    /// Apply glob overrides to one entry. `relative` is the entry's path
    /// from the search root, which a path-shaped inclusion matches against.
    /// Directory exclusions are not modeled, so a directory is never
    /// skipped by one here; a directory no path-shaped inclusion can reach
    /// past holds nothing the search reads, so it is.
    pub(super) fn override_for(&self, name: &str, relative: &str, is_directory: bool) -> Override {
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
        if self.includes(name, relative) {
            return Override::Searched;
        }
        if is_directory && (!self.path_shaped || self.reaches_past(relative)) {
            Override::Undecided
        } else {
            Override::Skipped
        }
    }

    /// Whether an inclusion can match a path below `relative`. A glob
    /// without a `/` matches a name at any depth, so it always can.
    fn reaches_past(&self, relative: &str) -> bool {
        self.include.iter().any(|pattern| {
            if !pattern.contains('/') {
                return true;
            }
            let mut components = pattern.split('/');
            for part in relative.split('/') {
                let Some(component) = components.next() else {
                    return false;
                };
                if component == "**" {
                    return true;
                }
                if !glob_matches(component, part).unwrap_or(true) {
                    return false;
                }
            }
            components.next().is_some()
        })
    }

    /// Whether an inclusion matches against the path from ripgrep's match
    /// base rather than an entry's name.
    pub(super) fn is_path_shaped(&self) -> bool {
        self.path_shaped
    }

    /// Whether ripgrep's walk enters `.git` rather than passing it over as
    /// a hidden directory: only an inclusion that matches it does that.
    pub(super) fn selects_git(&self, name: &str, relative: &str) -> bool {
        self.path_shaped && self.includes(name, relative)
    }

    fn includes(&self, name: &str, relative: &str) -> bool {
        self.include.iter().any(|pattern| {
            let text = if pattern.contains('/') {
                relative
            } else {
                name
            };
            glob_matches(pattern, text).unwrap_or(true)
        })
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
