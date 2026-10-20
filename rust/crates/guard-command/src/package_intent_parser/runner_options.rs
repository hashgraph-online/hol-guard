//! The package runners' own option tables.
//!
//! `npx` and `bunx` take options before the executable they run. Reading
//! those options is how the parser finds the executable at all, so the tables
//! live beside each other here rather than among the manager rules.
use super::*;

// package_intent_parser.py :67  `_LOCAL_EXECUTION_COMMANDS`
pub(super) static LOCAL_EXECUTION_COMMANDS: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| ["bunx", "npx"].into_iter().collect());

// package_intent_parser.py :98-103  `_LOCAL_EXECUTION_FLAGS_BY_COMMAND`
pub(super) fn local_execution_flags(command: &str) -> &'static [&'static str] {
    match command {
        "bunx" => &["--bun", "--no-install", "--"],
        // The options past the first two name no package: they answer the
        // install prompt, choose between the cache and the registry, or set
        // how much the runner prints. The executable they precede is still
        // the one this reads.
        "npx" => &[
            "--no",
            "--no-install",
            "--",
            "--yes",
            "-y",
            "--offline",
            "--prefer-offline",
            "--prefer-online",
            "--quiet",
            "-q",
            "--silent",
            "-s",
        ],
        _ => &[],
    }
}
