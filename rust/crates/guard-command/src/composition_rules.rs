//! Rust port of `runtime/composition_rules.py` — signal composition rules
//! for Guard detector action decisions.
//!
//! The canonical implementation lives in
//! `guard_contracts::decision_lattice` (ported there alongside
//! `action_lattice.py` because `CompositionResult` and `GuardAction` are
//! shared contract types). This module re-exports the surface so in-crate
//! callers keep the `crate::composition_rules::…` path the Python module
//! layout implies.

pub use guard_contracts::{compose_action_from_signals, CompositionResult};
