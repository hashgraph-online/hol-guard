//! Plain-HTTP startup translation; backend availability remains native-owned.
use super::{inputs, Builder, Code, Result, Uncertainty};
use crate::bash_approval::Operation;

impl Builder<'_> {
    pub(super) fn curl_startup(
        &mut self,
        operation: &Operation,
        resolved: &str,
        config: Code,
        launch: String,
    ) -> Result<String> {
        let unproven = || Uncertainty {
            reason: "bash_curl_startup_unproven",
            line: operation.line,
        };
        if resolved != "/usr/bin/curl"
            || !crate::bash_approval::curl_startup::inert_openssl_config(&config.source)
        {
            return Err(unproven());
        }
        self.register(&config, inputs::Kind::Startup)?;
        // This translation is valid only for proven plain HTTP with dormant
        // crypto configuration. The OS backend preserves HTTP bytes without
        // opening the live LibreSSL configuration. The native owner must
        // verify backend support before offering execution consent.
        if crate::pretool::bound_curl_read_destinations(
            &operation.argv,
            crate::pretool::PathContext {
                home_dir: self.environment.get("HOME").map(String::as_str),
                ..Default::default()
            },
        )
        .is_none()
        {
            return Err(unproven());
        }
        Ok(format!("CURL_SSL_BACKEND=secure-transport {launch}"))
    }
}
