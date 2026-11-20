//! The status-safe failure for a hook-manifest authentication reason, as
//! `manifest_refusal` reports it: a key the runtime cannot use is
//! "unavailable"; every other reason keeps its code and carries one message.

pub(crate) const UNAVAILABLE: (&str, &str) = (
    "codex_hook_manifest_verification_unavailable",
    "Guard could not verify the Codex hook installation; run repair and retry.",
);

/// `manifest_refusal`: the status-safe failure for an authentication reason.
pub(crate) fn refusal(reason: &str) -> (String, String) {
    if matches!(reason, "runtime_unavailable" | "invalid") {
        return (UNAVAILABLE.0.to_owned(), UNAVAILABLE.1.to_owned());
    }
    let message = match reason {
        "codex_hook_manifest_missing" => {
            "The authenticated Codex hook manifest is missing; run `hol-guard install codex` to repair it."
        }
        "codex_hook_manifest_not_regular" => {
            "The Codex hook manifest must be a private regular file, not a symlink."
        }
        "codex_hook_manifest_owner_mismatch" => "The Codex hook manifest has an unexpected owner.",
        "codex_hook_manifest_permissions_unsafe" => {
            "The Codex hook manifest permissions are not owner-only."
        }
        "codex_hook_manifest_invalid" => {
            "The authenticated Codex hook manifest is unreadable; run `hol-guard install codex` to repair it."
        }
        "codex_hook_manifest_authentication_missing" => {
            "The Codex hook manifest is not authenticated; run `hol-guard install codex` to repair it."
        }
        "codex_hook_manifest_authentication_invalid" => {
            "The Codex hook manifest authentication metadata is invalid; repair the Codex installation."
        }
        "codex_hook_manifest_key_mismatch" | "codex_hook_manifest_installation_mismatch" => {
            "The Codex hook manifest belongs to another Guard installation; run `hol-guard install codex`."
        }
        "codex_hook_manifest_mac_invalid" => {
            "The Codex hook manifest authentication failed; run `hol-guard install codex` to repair it."
        }
        "codex_hook_manifest_secret_missing" => {
            "The private Codex hook authentication key is missing; run `hol-guard install codex` to repair it."
        }
        _ => {
            "The private Codex hook authentication key is not usable; repair the Codex installation."
        }
    };
    (reason.to_owned(), message.to_owned())
}
