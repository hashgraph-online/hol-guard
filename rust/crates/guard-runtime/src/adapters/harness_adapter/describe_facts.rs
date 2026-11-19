//! The facts a `Spec` answers about itself.

use serde_json::{json, Value};

use super::Spec;

impl Spec {
    /// Cline picks its hook transport from whether the runtime is frozen.
    pub(crate) fn frozen_fact(&self) -> bool {
        self.harness == "cline"
    }

    /// The Pi family renders an extension that runs this Guard process.
    pub(crate) fn extension(&self) -> bool {
        matches!(self.harness, "pi" | "omp")
    }

    /// The default approval flow, as `HarnessAdapter.approval_flow` answers it.
    pub(crate) fn approval_flow(&self) -> Value {
        json!({
            "tier": self.tier,
            "summary": self.summary,
            "fallback_hint": self.fallback,
            "prompt_channel": self.channel,
            "auto_open_browser": self.auto_open,
        })
    }
}
