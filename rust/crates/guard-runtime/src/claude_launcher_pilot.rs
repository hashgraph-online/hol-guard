//! Qualification-only native Claude bootstrap. No normal adapter selects it.

#[cfg(target_os = "linux")]
#[path = "claude_launcher_pilot_linux.rs"]
mod linux;

pub(crate) fn run(path: &std::path::Path, event: &str) -> std::result::Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        linux::run(path, event).map_err(|_| "claude_native_launcher_pilot_failed".to_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, event);
        Err("claude_native_launcher_pilot_platform_unsupported".to_owned())
    }
}
