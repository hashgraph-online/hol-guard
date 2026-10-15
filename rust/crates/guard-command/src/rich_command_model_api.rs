//! Narrow public surface for resident access to the existing model helpers.
pub use crate::command_segment_parsing::shell_tokens_without_redirects;
pub use crate::command_structure::{
    build_command_security_identity, extract_command_redirects, CommandRedirect, EmbeddedCommand,
    IdentitySegment,
};
pub use crate::command_tokens::{
    after_sudo_options, executable_name, leading_environment, shell_tokens, windows_shell_tokens,
};
pub use crate::env_wrapper::parse_env_wrapper;
pub use crate::shell_structure::ShellHeredoc;
