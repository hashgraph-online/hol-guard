//! `runner_authority` kind `gemini_detect`: parse the request and run the
//! Gemini discovery leaf over the shared inventory, then finish the kind
//! result. The parsing and artifact discovery live in
//! `guard_adapter_detection::gemini`; the inventory, skill walk and wire
//! assembly stay here.

use serde_json::Value;

use super::adapter_inventory::{Inventory, Request};
use super::runner_authority_op::KindResult;

const HARNESS: &str = "gemini";

pub(crate) fn detect(args: &Value) -> KindResult {
    let request = Request::parse(args, HARNESS)?;
    let mut inventory = Inventory::new(&request);
    guard_adapter_detection::gemini::detect(
        &mut inventory,
        &guard_adapter_detection::DetectionRequest {
            home: request.home.clone(),
            workspace: request.workspace.clone(),
        },
    )?;
    inventory.finish()
}
