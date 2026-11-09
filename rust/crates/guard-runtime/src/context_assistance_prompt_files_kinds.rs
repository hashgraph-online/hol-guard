//! Which project files the prompt walk reads for context, and what it still
//! learns from the ones it leaves out.
use crate::context_assistance_prompt_words::spelled;
use std::path::Path;

const TEXT_EXTENSIONS: &[&str] = &[
    "adoc", "astro", "c", "cc", "cjs", "clj", "cpp", "cs", "css", "dart", "erl", "ex", "exs", "go",
    "gradle", "graphql", "h", "hpp", "html", "java", "js", "json", "jsx", "kt", "kts", "less",
    "lua", "m", "md", "mdx", "mjs", "mm", "nix", "php", "proto", "py", "r", "rb", "rs", "rst",
    "sass", "scala", "scss", "sh", "sql", "svelte", "swift", "toml", "ts", "tsx", "txt", "vue",
    "xml", "yaml", "yml", "zig",
];
const SKIPPED_FILES: &[&str] = &[
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Cargo.lock",
    "poetry.lock",
    "Gemfile.lock",
    "composer.lock",
    "go.sum",
    "uv.lock",
];

/// Formats with a NUL byte in their first few bytes, where `rg` stops, so
/// no name can be found in them and they need not be read.
const BINARY_EXTENSIONS: &[&str] = &[
    "gz", "ico", "jpeg", "jpg", "otf", "png", "pyc", "ttf", "whl", "woff", "woff2", "zip",
];

pub(crate) fn wanted_file(name: &str) -> bool {
    if SKIPPED_FILES.contains(&name) || name.ends_with(".min.js") || name.ends_with(".min.css") {
        return false;
    }
    Path::new(name)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| TEXT_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
}

/// Whether `name` is a format `rg` finds nothing in, by its extension.
pub(crate) fn binary(name: &str) -> bool {
    (Path::new(name).extension().and_then(|ext| ext.to_str()))
        .is_some_and(|ext| BINARY_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
}

/// For each of `terms`, whether a file the walk leaves out for its kind,
/// such as `setup.cfg`, a `.pyi` stub or a `Makefile`, spells it as the walk
/// counts spellings; `None` when it cannot be read. `rg` searches these
/// files too, so a note saying no other file holds a name has to look in
/// them. Text after a NUL byte is left alone, as `rg` stops at one.
pub(crate) fn left_out(path: &Path, max: usize, terms: &[String]) -> Option<Vec<bool>> {
    let read = guard_secure_fs::read_bounded(path, max).ok()?;
    let end = (read.bytes.iter()).position(|&byte| byte == 0);
    let text = String::from_utf8_lossy(&read.bytes[..end.unwrap_or(read.bytes.len())]);
    let text = text.to_lowercase();
    let hits: Vec<u8> = (terms.iter())
        .map(|term| u8::from(text.contains(term.as_str())))
        .collect();
    Some(spelled(&text, terms, &hits))
}
