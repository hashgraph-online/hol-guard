use super::*;

fn document(id: &str, text: &str) -> ContextDocument {
    ContextDocument {
        id: id.into(),
        text: text.into(),
        start_line: 1,
    }
}

#[path = "broker_validation_tests.rs"]
mod validation;
