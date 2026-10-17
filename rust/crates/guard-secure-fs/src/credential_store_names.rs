//! The hidden directories that hold credentials, and the file names that hold
//! them directly.
//!
//! Two screens read these lists. A listing prints entry names and nothing else,
//! so it refuses only the directories whose names reveal which accounts, hosts
//! and keys exist. A content read returns the bytes, so it refuses those same
//! directories and, on top of them, the file names a token or a settings file
//! is normally written under. Keeping both lists here is what stops the two from drifting apart,
//! which is how a directory ends up guarded against listing and open to `cat`.

use std::path::{Component, Path};

/// Directories a harness, editor or git hook runner auto-loads from.
pub const HARNESS_DIRECTORIES: &[&str] = &[
    ".agent",
    ".agents",
    ".amazonq",
    ".antigravity",
    ".augment",
    ".claude",
    ".cline",
    ".clinerules",
    ".codex",
    ".continue",
    ".copilot",
    ".crush",
    ".cursor",
    ".devin",
    ".gemini",
    ".githooks",
    ".goose",
    ".grok",
    ".hermes",
    ".husky",
    ".junie",
    ".kimi",
    ".kiro",
    ".omp",
    ".openclaw",
    ".opencode",
    ".openhands",
    ".paseo",
    ".pi",
    ".qwen",
    ".roo",
    ".trae",
    ".windsurf",
    ".zcode",
    ".zed",
];

/// Hidden directories that hold credentials, keys, wallets, browser profiles
/// or Guard's own state. Their entry names alone reveal which accounts, hosts
/// and keys exist.
pub const CREDENTIAL_STORE_NAMES: [&str; 18] = [
    ".aws",
    ".azure",
    ".bitcoin",
    ".docker",
    ".electrum",
    ".ethereum",
    ".gcloud",
    ".gnupg",
    ".hol-guard",
    ".kube",
    ".mozilla",
    ".password-store",
    ".pki",
    ".ssh",
    ".terraform",
    ".terraform.d",
    ".thunderbird",
    ".vault-token",
];

/// Harness directories that share skills, rules or Git hooks rather than an
/// agent login. Every other harness directory (`~/.gemini`, `~/.omp`,
/// `~/.copilot`) may hold login tokens under names Guard does not know, so it
/// keeps review.
pub const HARNESS_SHARED_NAMES: [&str; 5] =
    [".agent", ".agents", ".clinerules", ".githooks", ".husky"];

/// Harness homes whose login and secret-bearing config live in files the
/// credential and hidden-name screens already refuse to read
/// (`auth.json`, `.credentials.json`, `config.toml`, `settings.json`).
/// Listing them prints plan, memory and session names, never a secret.
pub const HARNESS_HOME_NAMES: [&str; 2] = [".claude", ".codex"];

/// Credential, password-manager, keyring, browser-profile and agent-login
/// stores kept directly below `~/.config` or `~/.local/share`. A tool whose
/// directory holds only fixed-name config files (`~/.config/doctl/config.yaml`,
/// with its tokens inside the file) is not listed: its entry names reveal no
/// account, host or key, and content reads of the file stay guarded by
/// [`secret_bearing_file_name`].
pub const NESTED_CREDENTIAL_STORE_NAMES: [&str; 16] = [
    "1password",
    "bravesoftware",
    "chromium",
    "gcloud",
    "gh",
    "github-copilot",
    "gnupg",
    "google-chrome",
    "gopass",
    "hub",
    "keyrings",
    "microsoft-edge",
    "op",
    "opencode",
    "password-store",
    "solana",
];

/// File stems a token, key or session is conventionally written under. Below a
/// hidden directory this is where a tool's own secret lives, whatever the
/// directory is called: `~/.config/doctl/config.yaml` holds an API token, and
/// `doctl` is not a name any directory screen can be expected to know.
const SECRET_BEARING_STEMS: [&str; 27] = [
    "account",
    "accounts",
    "apps",
    "auth",
    "client_secret",
    "config",
    "configuration",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "hosts",
    "identity",
    "key",
    "keyring",
    "keyrings",
    "keys",
    "oauth_creds",
    "password",
    "passwords",
    "secret",
    "secrets",
    "service-account",
    "serviceaccount",
    "settings",
    "token",
    "tokens",
];

/// Suffixes that carry a key or certificate whatever the file is called.
const SECRET_BEARING_SUFFIXES: [&str; 8] = [
    ".cer",
    ".crt",
    ".jks",
    ".key",
    ".keystore",
    ".p12",
    ".pem",
    ".pfx",
];

/// A harness directory other than the shared skill and hook trees. Its
/// `plugins` subtree (`~/.zcode/cli/plugins/cache`) holds installed plugin
/// code rather than the login, so listings below it are screened like any
/// other dot-directory.
fn harness_login_store(name: &str) -> bool {
    HARNESS_DIRECTORIES.contains(&name)
        && !HARNESS_SHARED_NAMES.contains(&name)
        && !HARNESS_HOME_NAMES.contains(&name)
}

/// Whether any component of `names` is a credential store, where `names` is
/// already lowercased. Shared by the listing and content screens so a store
/// added to one list is refused by both.
pub fn names_hold_credential_store(names: &[String]) -> bool {
    names.iter().enumerate().any(|(index, name)| {
        let parent = index.checked_sub(1).map(|at| names[at].as_str());
        let grandparent = index.checked_sub(2).map(|at| names[at].as_str());
        let config_child =
            parent == Some(".config") || (parent == Some("share") && grandparent == Some(".local"));
        CREDENTIAL_STORE_NAMES.contains(&name.as_str())
            || (harness_login_store(name) && !names[index + 1..].iter().any(|n| n == "plugins"))
            || name.starts_with(".env")
            || (config_child && NESTED_CREDENTIAL_STORE_NAMES.contains(&name.as_str()))
    })
}

/// No component below the home directory is a credential store, and no store
/// sits directly below `.config` or `.local/share` on the way.
pub fn clears_store_screen(path: &Path) -> bool {
    !names_hold_credential_store(&lowered_names(path))
}

/// The lowercased ordinary components of `path`.
pub fn lowered_names(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

/// Whether `name`, a lowercased file name, is one a secret is normally written
/// under. A content read below a hidden directory refuses these; a listing does
/// not need to, because it never returns what is inside them.
pub fn secret_bearing_file_name(name: &str) -> bool {
    if SECRET_BEARING_SUFFIXES
        .iter()
        .any(|suffix| name.ends_with(suffix))
        // `id_ed25519`, `id_rsa.pub`: a private key is named for the algorithm,
        // not for what it is.
        || name.starts_with("id_")
    {
        return true;
    }
    // `.credentials.json` names the same thing `credentials.json` does, so the
    // leading dot is stripped before the stem is read.
    let bare = name.strip_prefix('.').unwrap_or(name);
    SECRET_BEARING_STEMS.contains(&bare.split('.').next().unwrap_or(bare))
}

/// Whether a search pattern can select a file a secret is kept in.
///
/// A pattern is not a file name: it selects whatever it matches, so a word the
/// pattern merely contains is a word the printed names can carry, and
/// `*config*` reaches `config.toml` as surely as `config.toml` does. The stems
/// and suffixes [`secret_bearing_file_name`] reads as a whole name are
/// therefore read here as substrings, and `env` and `id_` with them, because
/// an environment file and a private key are named for what they hold
/// wherever they sit.
///
/// A wildcard is read as the wildcard it is rather than as a character of its
/// own. `fd` takes its pattern as a regular expression and `find -name` takes
/// a glob, so `t.ken`, `cred?ntials` and `to*ken` each name the thing the
/// plain spelling does; a screen that reads the pattern's literal characters
/// alone sees three words it has never heard of. The pattern is matched
/// against each word in both directions, so a pattern shorter than the word
/// and one longer than it are both caught, and `*` is tried as nothing at all
/// as well as as a character, which is what lets `to*ken` reach `token`.
pub fn pattern_can_select_secret(pattern: &str) -> bool {
    let lowered = pattern.to_ascii_lowercase();
    let spellings = [lowered.replace('*', ""), lowered];
    SECRET_BEARING_STEMS
        .iter()
        .chain(SECRET_BEARING_SUFFIXES.iter())
        .chain(["env", "id_"].iter())
        .any(|word| {
            spellings
                .iter()
                .any(|spelling| wildcards_reach(spelling, word))
        })
}

/// Whether `pattern`, whose `.`, `?` and `*` stand for any character, and
/// `word` name the same thing anywhere they overlap.
pub fn wildcards_reach(pattern: &str, word: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let word: Vec<char> = word.chars().collect();
    if pattern.is_empty() || word.is_empty() {
        return false;
    }
    let aligned = |pattern: &[char], word: &[char]| {
        pattern
            .iter()
            .zip(word)
            .all(|(spelled, letter)| matches!(spelled, '.' | '?' | '*') || spelled == letter)
    };
    if pattern.len() >= word.len() {
        pattern.windows(word.len()).any(|at| aligned(at, &word))
    } else {
        word.windows(pattern.len()).any(|at| aligned(&pattern, at))
    }
}

/// Download caches. A cache holds third-party bytes a package manager
/// fetched, which is not what this rule was opened for, and the package
/// source rule already refuses to treat one as an install root.
fn download_cache(name: &str) -> bool {
    matches!(name, "cache" | "caches" | ".cache" | "_cacache")
}

/// Whether a narrower rule already owns every read below `parents`.
///
/// A harness directory mixes documents with an account: `~/.claude/projects`
/// holds whole transcripts, `~/.codex/auth.json` is the login, and
/// `~/.agents/skills` is a `.md` tree whose sibling scripts are deliberately
/// left outside the read rules. Each of those has a rule of its own with
/// bounds a target screen cannot see, so this rule stands aside rather than
/// giving the same path a second, looser answer.
fn curated_tree_owns(parents: &[String]) -> bool {
    parents
        .first()
        .is_some_and(|first| HARNESS_DIRECTORIES.contains(&first.as_str()))
        || parents.iter().any(|name| download_cache(name))
}

/// Names prose is written under. A token is not written in Markdown, so a
/// guidance document keeps the one place below a hidden directory that a
/// tool's own configuration also occupies.
fn documentation_name(name: &str) -> bool {
    [".md", ".markdown", ".rst"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

/// Whether the file sits in a directory a tool keeps its programs in.
///
/// `~/.bun/bin/bun` is an executable, not content a task reads: its bytes are
/// a program, and a listing already answers the question an agent actually
/// asks there, which is whether the tool is installed. The install roots this
/// screen would otherwise open (`~/.cargo/bin`, `~/.local/bin`) are also where
/// a link can point somewhere else entirely, so the directory keeps its review
/// and the metadata screen keeps the benign half. A subdirectory of one holds
/// the same thing a level down (`~/.local/bin/helpers/run`), so every parent
/// is read rather than only the one the file sits in.
fn program_directory(parents: &[String]) -> bool {
    parents.iter().any(|name| name == "bin" || name == "sbin")
}

/// How deep the directory a tool owns sits below the home directory.
///
/// Usually it is the hidden directory itself (`~/.ngrok2`). Below `~/.config`
/// and `~/.local/share` it is the next component down (`~/.config/ngrok`),
/// because those two are shared roots rather than one tool's directory.
fn tool_root_depth(parents: &[String]) -> usize {
    match parents.first().map(String::as_str) {
        Some(".config") => 2,
        Some(".local") if parents.get(1).is_some_and(|name| name == "share") => 3,
        _ => 1,
    }
}

/// Whether the file sits where a tool keeps its own configuration: directly
/// inside the directory that tool owns, or above it.
///
/// `~/.ngrok2/ngrok.yml` holds an authtoken, `~/.config/ngrok/ngrok.yml` the
/// same one, `~/.config/configstore/firebase-tools.json` a refresh token and
/// `~/.secrets/prod.yaml` whatever the name promises. None of those names is
/// one a stem list can be expected to know, and the list would never finish:
/// every tool invents its own. What they share is the slot. A file further
/// down is content the tool manages — a workflow, a package, a vendored crate
/// — which is the shape this rule was opened for.
fn tool_configuration_slot(parents: &[String], name: &str) -> bool {
    parents.len() <= tool_root_depth(parents) && !documentation_name(name)
}

/// Whether a content read may cross the hidden components of `lowered`, the
/// lowercased names a path has below the home directory.
///
/// One hidden directory directly below home, holding ordinary files: that is
/// the shape an agent reads all day (`~/.github/workflows/ci.yml`,
/// `~/.hol-support/SAFETY.md`, a toolchain's `package.json`) and the shape the
/// approval queue filled up with. Everything else keeps its review:
///
/// - a file directly below home (`~/.npmrc`, `~/.zshrc`), which is a tool's
///   own configuration rather than a directory of content;
/// - a hidden component below the first, which is private state of the tool
///   that owns the directory, the same rule the listing screen applies;
/// - a program directory, per [`program_directory`];
/// - a credential store at any depth, and a file named the way a token, key
///   or settings file conventionally is;
/// - a tool's own configuration, per [`tool_configuration_slot`];
/// - a tree a narrower rule already owns, per [`curated_tree_owns`].
pub fn hidden_content_read_allowed(lowered: &[String]) -> bool {
    let Some((name, parents)) = lowered.split_last() else {
        return false;
    };
    parents.first().is_some_and(|first| first.starts_with('.'))
        && !parents.iter().skip(1).any(|part| part.starts_with('.'))
        && !name.starts_with('.')
        && !curated_tree_owns(parents)
        && !tool_configuration_slot(parents, name)
        && !program_directory(parents)
        && !names_hold_credential_store(lowered)
        && !secret_bearing_file_name(name)
}

/// Paths a narrower rule already answers, with bounds this screen cannot see.
///
/// `sfrs_agent_guidance` in the command crate admits `sed -n '1,200p' ~/.hol-support/SAFETY.md`
/// and refuses the same file at 501 lines or over a reversed range, and the
/// skill-document rule answers a `SKILL.md` the same way. A target screen sees
/// neither bound, so where one of those rules owns the path its verdict stands
/// rather than being given a second, looser answer here.
pub fn narrow_guidance_rule_owns(lowered: &[String]) -> bool {
    match lowered.last().map(String::as_str) {
        // The skill-document rule knows which roots each harness supports;
        // this screen sees only that a file is called `SKILL.md`, so a copy
        // outside those roots would otherwise read.
        Some("skill.md") => true,
        Some("safety.md") => lowered.iter().any(|part| part == ".hol-support"),
        _ => false,
    }
}
