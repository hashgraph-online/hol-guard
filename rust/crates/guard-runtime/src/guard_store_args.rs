//! Typed access to a method's `args` object. Any shape outside the method's
//! contract fails closed with `native_guard_store_args_invalid`.

use serde_json::{Map, Value};

use crate::guard_store_db::{StoreError, StoreResult};

const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");

pub(crate) struct Args<'a>(pub(crate) &'a Map<String, Value>);

impl<'a> Args<'a> {
    pub(crate) fn raw(&self, key: &str) -> Option<&'a Value> {
        self.0.get(key).filter(|value| !value.is_null())
    }

    pub(crate) fn str(&self, key: &str) -> StoreResult<&'a str> {
        self.raw(key).and_then(Value::as_str).ok_or(INVALID)
    }

    pub(crate) fn opt_str(&self, key: &str) -> StoreResult<Option<&'a str>> {
        match self.raw(key) {
            None => Ok(None),
            Some(value) => value.as_str().map(Some).ok_or(INVALID),
        }
    }

    pub(crate) fn int(&self, key: &str) -> StoreResult<i64> {
        self.raw(key).and_then(Value::as_i64).ok_or(INVALID)
    }

    pub(crate) fn flag(&self, key: &str) -> StoreResult<bool> {
        match self.raw(key) {
            None => Ok(false),
            Some(value) => value.as_bool().ok_or(INVALID),
        }
    }

    pub(crate) fn ints(&self, key: &str) -> StoreResult<Vec<i64>> {
        self.raw(key)
            .and_then(Value::as_array)
            .ok_or(INVALID)?
            .iter()
            .map(|value| value.as_i64().ok_or(INVALID))
            .collect()
    }

    pub(crate) fn strings(&self, key: &str) -> StoreResult<Option<Vec<&'a str>>> {
        let Some(value) = self.raw(key) else {
            return Ok(None);
        };
        value
            .as_array()
            .ok_or(INVALID)?
            .iter()
            .map(|item| item.as_str().ok_or(INVALID))
            .collect::<StoreResult<Vec<_>>>()
            .map(Some)
    }

    pub(crate) fn object(&self, key: &str) -> StoreResult<&'a Map<String, Value>> {
        self.raw(key).and_then(Value::as_object).ok_or(INVALID)
    }

    pub(crate) fn opt_object(&self, key: &str) -> StoreResult<Option<&'a Map<String, Value>>> {
        match self.raw(key) {
            None => Ok(None),
            Some(value) => value.as_object().map(Some).ok_or(INVALID),
        }
    }

    /// The four delivery-binding parts under `prefix` keys, in canonical order.
    pub(crate) fn identity(&self) -> [Option<&'a Value>; 4] {
        [
            self.raw("oauth_subject_hash"),
            self.raw("workspace_id"),
            self.raw("machine_id"),
            self.raw("machine_installation_id"),
        ]
    }
}
