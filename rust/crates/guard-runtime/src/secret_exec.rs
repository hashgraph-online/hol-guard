//! Secret execution refuses requests until the resident has an approval and launch binding.

use serde_json::json;

pub(crate) const COMMAND: &str = "secret-exec";

pub(crate) fn unavailable() -> serde_json::Value {
    json!({"ok": false, "error": "secret_execution_binding_unavailable"})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_execution_is_unavailable_without_resident_authority() {
        assert_eq!(
            unavailable(),
            json!({"ok": false, "error": "secret_execution_binding_unavailable"})
        );
    }
}
