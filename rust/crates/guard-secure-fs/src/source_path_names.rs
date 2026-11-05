//! The name tables the source-path screens read: which extensions count
//! as source, which dotfiles a project owns, which names mark a
//! credential or a tool's own login. They are data rather than logic, and
//! every one of them is consulted by `source_path.rs` alone.

pub(super) const SOURCE_INSPECTION_PARTS: &[&str] = &[
    "__tests__",
    "app",
    "constants",
    "dashboard",
    "docs",
    "lib",
    "packages",
    "scripts",
    "src",
    "test",
    "tests",
    "workers",
];
pub(super) const SOURCE_EXTENSIONS: &[&str] = &[
    "c", "cc", "cpp", "css", "go", "h", "hpp", "html", "java", "js", "jsx", "json", "md", "mjs",
    "py", "rs", "sh", "toml", "ts", "tsx", "yaml", "yml",
];
pub(super) const BENIGN_SOURCE_DOTFILES: &[&str] = &[".nvmrc", ".worktrees"];
/// Ordinary project config files. They are benign only as the final path
/// component, so a directory spelled `.gitignore/` opens no hidden tree.
///
/// This list is the write-safe half: a redirect may land on one of these
/// names without leaving the bounded projection. Everything a project only
/// ever reads back belongs in [`BENIGN_PROJECT_READ_DOTFILES`] instead,
/// because a name that is harmless to read is not therefore harmless to
/// overwrite -- `.gitattributes` names filter drivers Git runs on checkout.
pub(super) const BENIGN_PROJECT_DOTFILES: &[&str] = &[
    ".dockerignore",
    ".editorconfig",
    ".eslintignore",
    ".gitignore",
    ".prettierignore",
];
/// Project config files that a read admits and a write does not.
///
/// Each name has a fixed meaning the ecosystem gave it: a browser target
/// list, a git attribute table, an ignore list, or a pinned toolchain
/// version. None of them is where a tool writes a login, and
/// `sensitive_path_family` screens the basename before this list is read, so
/// a project that spells one of these next door is read rather than queued
/// for an approval nobody can answer. A placeholder such as `.keep` is not
/// here: it has no ecosystem-defined contents, so it stays on the existing
/// empty-marker route, which admits it only while it is empty.
pub(super) const BENIGN_PROJECT_READ_DOTFILES: &[&str] = &[
    ".browserslistrc",
    ".gitattributes",
    ".go-version",
    ".java-version",
    ".node-version",
    ".npmignore",
    ".python-version",
    ".ruby-version",
    ".stylelintignore",
    ".terraform-version",
    ".tool-versions",
];
/// Formatter, linter and test-runner rc files. Each is also spelled with one
/// of [`PROJECT_CONFIG_EXTENSIONS`] -- `.prettierrc.json`, `.mocharc.yml` --
/// so the stem is matched once rather than every spelling enumerated.
pub(super) const BENIGN_PROJECT_DOTFILE_STEMS: &[&str] = &[
    ".babelrc",
    ".c8rc",
    ".eslintrc",
    ".mocharc",
    ".nycrc",
    ".prettierrc",
    ".stylelintrc",
    ".swcrc",
    ".taprc",
];
/// The config extensions the rc files above carry. Exactly one is accepted,
/// so `.eslintrc.json.enc` keeps its review rather than reading as config.
pub(super) const PROJECT_CONFIG_EXTENSIONS: &[&str] = &[
    "cjs", "cts", "js", "json", "json5", "mjs", "mts", "toml", "ts", "yaml", "yml",
];
pub(super) const SENSITIVE_SEARCH_BASENAMES: &[&str] = &[
    ".aws",
    ".docker",
    ".env",
    ".git-credentials",
    ".kube",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".ssh",
    "credentials",
    "id_rsa",
];
/// Path components that mark credential/secret material when a read
/// escapes the workspace. Shared with the native PreToolUse read floor.
pub const EXTERNAL_SENSITIVE_PARTS: &[&str] = &[
    ".aws",
    ".docker",
    ".env",
    ".git-credentials",
    ".kube",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".ssh",
    "auth",
    "authorization",
    "credential",
    "credentials",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "kubeconfig",
    "passwd",
    "password",
    "private-key",
    "private_key",
    "secret",
    "secrets",
    "token",
    "tokens",
];
pub(super) const KNOWN_SKILL_DOC_ROOTS: &[&str] = &[
    ".codex/superpowers/skills",
    ".codex/skills",
    ".agents/skills",
    ".agent/skills",
    ".claude/skills",
];
/// Home roots where coding agents keep their own Markdown documents: OMP
/// artifacts and the plan files Claude Code and Codex users write and read
/// back. Only plain `.md` files below them qualify; see
/// `known_artifact_doc_path`.
pub(super) const KNOWN_AGENT_DOC_ROOTS: &[&str] =
    &[".agent/artifacts", ".claude/plans", ".codex/plans"];

/// Extensions a project writes its own configuration and prose under. A
/// credential file conventionally carries none of them: `.netrc`, `.npmrc`,
/// `.pgpass` and `.git-credentials` are named for what they hold and end
/// there, so requiring one of these already separates a project's documents
/// from a store of logins.
pub(super) const PROJECT_DOCUMENT_EXTENSIONS: &[&str] = &[
    "cfg", "conf", "ini", "json", "jsonc", "markdown", "md", "toml", "txt", "yaml", "yml",
];

/// Words that name a tool's own login or keystore rather than a project's
/// configuration, read over the name's parts so `.mcp.json` and
/// `.claude.json` keep their review wherever they sit.
pub(super) const TOOL_LOGIN_WORDS: &[&str] = &[
    "agent",
    "agents",
    "aider",
    "aws",
    "azure",
    "claude",
    "codex",
    "copilot",
    "cursor",
    "docker",
    "dockercfg",
    "gcloud",
    "gemini",
    "gnupg",
    "gpg",
    "hgrc",
    "htpasswd",
    "keychain",
    "keyring",
    "keystore",
    "kube",
    "kubeconfig",
    "mcp",
    "netrc",
    "npmrc",
    "omp",
    "pgpass",
    "pypirc",
    "ssh",
    "vault",
    "vscode",
    "windsurf",
];

/// The entries of [`TOOL_LOGIN_WORDS`] that are a login file's whole name
/// rather than a vendor's. The rest of that list -- `docker`, `claude`,
/// `aws`, `agent` -- names a tool, and a repository names its own documents
/// after the tools it uses: `.github/workflows/docker.yml` and
/// `.well-known/agent.json` are the checkout's content, not a login. A caller
/// that already knows the name is a plain file inside the work tree reads it
/// against this half.
pub(super) const TOOL_LOGIN_FILE_WORDS: &[&str] = &[
    "dockercfg",
    "hgrc",
    "htpasswd",
    "keychain",
    "keyring",
    "keystore",
    "kubeconfig",
    "mcp",
    "netrc",
    "npmrc",
    "pgpass",
    "pypirc",
];
