use serde_json::{Map, Value};

/// Settings only the native runtime acts on. Python passes them through to the
/// settings response untouched under `native_settings`, without naming them.
const NATIVE_ONLY_KEYS: [&str; 1] = ["harness_cigar"];

pub(super) fn python_view(mut config: Value) -> Value {
    let mut native = Map::new();
    if let Some(fields) = config.as_object_mut() {
        for key in NATIVE_ONLY_KEYS {
            if let Some(value) = fields.remove(key) {
                native.insert(key.to_owned(), value);
            }
        }
        fields.insert("native_settings".to_owned(), Value::Object(native));
    }
    config
}
