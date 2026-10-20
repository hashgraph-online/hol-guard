//! Static key and tool-name tables for the hook action envelope.

pub(crate) const PATH_KEYS: &[&str] = &[
    "path",
    "paths",
    "file_path",
    "file_paths",
    "filePath",
    "filePaths",
    "filepath",
    "file",
    "files",
    "filename",
    "filenames",
    "target_path",
    "target_paths",
    "targetPath",
    "targetPaths",
    "target_directory",
    "targetDirectory",
    "directory",
    "dir",
];
pub(crate) const COMMAND_KEYS: &[&str] = &[
    "command",
    "cmd",
    "shell_command",
    "shellCommand",
    "pattern",
    "query",
    "search",
    "regex",
];
pub(crate) const EXPLICIT_COMMAND_KEYS: &[&str] =
    &["command", "cmd", "shell_command", "shellCommand"];
pub(crate) const SEARCH_PATTERN_KEYS: &[&str] = &["pattern", "query", "search", "regex"];
pub(crate) const PATCH_INPUT_KEYS: &[&str] = &["patch", "input", "command"];
pub(crate) const SHELL_TOOL_NAMES: &[&str] = &[
    "bash",
    "shell",
    "sh",
    "zsh",
    "terminal",
    "run_command",
    "run_terminal_command",
];
pub(crate) const FILE_READ_TOOL_NAMES: &[&str] = &[
    "read",
    "read_file",
    "open_file",
    "view",
    "view_file",
    "cat_file",
];
pub(crate) const FILE_WRITE_TOOL_NAMES: &[&str] = &[
    "write",
    "edit",
    "multiedit",
    "strreplace",
    "delete",
    "delete_file",
    "write_file",
    "edit_file",
    "apply_patch",
];
pub(crate) const CURSOR_NETWORK_TOOL_NAMES: &[&str] = &[
    "webfetch",
    "websearch",
    "fetch_web_content",
    "web_fetch",
    "web_search",
    "browser",
    "browser_action",
    "open_url",
    "visit_url",
];
pub(crate) const CURSOR_NETWORK_URL_KEYS: &[&str] = &["url", "urls", "link", "links"];
