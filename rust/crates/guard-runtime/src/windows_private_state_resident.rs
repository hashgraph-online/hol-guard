//! Resident `windows_private_state` operation: the `windows-private-state
//! --stdin` reads, writes, deletes and directory repairs, answered inside the
//! resident so a daemon worker that already holds a resident client starts no
//! process per owner-private state op.
//!
//! The same held directory handles and owner/DACL checks run. Only paths
//! inside the resident's own Guard home are served: the dispatcher pins
//! `guard_home` to the resident's home first, and the directory and private
//! root must lie under it. The file op's answer, including its operational
//! failure code, comes back under `answer`; a frame without this schema is a
//! resident or transport failure, after which the client starts the one-shot
//! command instead.

use serde::Deserialize;
use serde_json::json;

use super::{answer, is_absolute, is_within, PrivateStore, Request, SystemStore};

pub(crate) const FEATURE: &str = "native-windows-private-state-resident-v1";
const SCHEMA: &str = "windows-private-state-resident.v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResidentRequest {
    pub(crate) guard_home: String,
    state: Request,
}

pub(crate) fn evaluate(request: &ResidentRequest) -> Result<Vec<u8>, String> {
    evaluate_with(request, &SystemStore)
}

fn evaluate_with<S: PrivateStore>(request: &ResidentRequest, store: &S) -> Result<Vec<u8>, String> {
    let home = request.guard_home.as_str();
    let state = &request.state;
    let inside = |path: &str| is_absolute(path) && is_within(path, home);
    if !is_absolute(home)
        || !inside(&state.directory)
        || state
            .private_root
            .as_deref()
            .is_some_and(|root| !inside(root))
    {
        return Err("native_windows_private_state_outside_guard_home".to_owned());
    }
    let answer = answer(state, store).unwrap_or_else(|code| json!({ "error": code }));
    serde_json::to_vec(&json!({ "schema": SCHEMA, "answer": answer }))
        .map_err(|_| "windows_private_state_response_encode_failed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Recorder {
        calls: RefCell<Vec<String>>,
    }

    impl PrivateStore for Recorder {
        fn read(
            &self,
            directory: &str,
            name: &str,
            _: u64,
            _: Option<&str>,
        ) -> Result<Option<Vec<u8>>, String> {
            self.calls
                .borrow_mut()
                .push(format!("read {directory} {name}"));
            Ok(Some(b"{}".to_vec()))
        }

        fn write(&self, directory: &str, name: &str, _: &[u8], _: &str) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("write {directory} {name}"));
            Ok(())
        }

        fn delete(&self, directory: &str, name: &str, _: &str) -> Result<bool, String> {
            self.calls
                .borrow_mut()
                .push(format!("delete {directory} {name}"));
            Err("native_resident_windows_access_denied".to_owned())
        }

        fn ensure(&self, directory: &str, _: &str) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("ensure {directory}"));
            Ok(())
        }
    }

    fn request(state: Value) -> ResidentRequest {
        serde_json::from_value(
            json!({ "guard_home": r"C:\Users\guard\.hol-guard", "state": state }),
        )
        .unwrap()
    }

    fn evaluated(state: Value, store: &Recorder) -> Result<Value, String> {
        evaluate_with(&request(state), store).map(|bytes| serde_json::from_slice(&bytes).unwrap())
    }

    #[test]
    fn answers_file_ops_inside_the_guard_home_under_the_resident_schema() {
        let store = Recorder::default();
        let read = evaluated(
            json!({
                "schema": "windows-private-state.v1", "op": "read",
                "directory": r"C:\Users\guard\.hol-guard\native-runtime", "name": "a.json",
                "private_root": r"C:\Users\guard\.hol-guard", "maximum_bytes": 8,
            }),
            &store,
        )
        .unwrap();
        assert_eq!(
            read,
            json!({ "schema": SCHEMA, "answer": { "content_b64": "e30=" } })
        );
        let ensure = evaluated(
            json!({
                "schema": "windows-private-state.v1", "op": "ensure",
                "directory": r"c:/users/guard/.hol-guard",
            }),
            &store,
        )
        .unwrap();
        assert_eq!(ensure["answer"], json!({ "ensured": true }));
        assert_eq!(
            store.calls.borrow().as_slice(),
            [
                r"read C:\Users\guard\.hol-guard\native-runtime a.json",
                "ensure c:/users/guard/.hol-guard",
            ]
        );
    }

    #[test]
    fn operational_failures_stay_inside_the_answer() {
        let store = Recorder::default();
        let deleted = evaluated(
            json!({
                "schema": "windows-private-state.v1", "op": "delete",
                "directory": r"C:\Users\guard\.hol-guard\native-runtime\direct-lane", "name": "ack.json",
                "private_root": r"C:\Users\guard\.hol-guard",
            }),
            &store,
        )
        .unwrap();
        assert_eq!(
            deleted["answer"],
            json!({ "error": "native_resident_windows_access_denied" })
        );
        let malformed = evaluated(
            json!({
                "schema": "windows-private-state.v1", "op": "read",
                "directory": r"C:\Users\guard\.hol-guard", "name": r"..\x", "maximum_bytes": 8,
            }),
            &store,
        )
        .unwrap();
        assert_eq!(
            malformed["answer"],
            json!({ "error": "windows_private_state_request_invalid" })
        );
        assert_eq!(store.calls.borrow().len(), 1);
    }

    #[test]
    fn refuses_paths_outside_the_guard_home_before_touching_them() {
        let store = Recorder::default();
        for state in [
            json!({
                "schema": "windows-private-state.v1", "op": "read",
                "directory": r"C:\Users\guard\.hol-guard-other", "name": "a.json", "maximum_bytes": 8,
            }),
            json!({
                "schema": "windows-private-state.v1", "op": "write",
                "directory": r"C:\Users\guard\.hol-guard\native-runtime", "name": "a.json",
                "private_root": r"C:\Users\guard", "maximum_bytes": 8, "content_b64": "e30=",
            }),
            json!({
                "schema": "windows-private-state.v1", "op": "ensure",
                "directory": r"C:\Users\guard\.hol-guard\..\elsewhere",
            }),
        ] {
            assert_eq!(
                evaluated(state, &store),
                Err("native_windows_private_state_outside_guard_home".to_owned())
            );
        }
        assert!(store.calls.borrow().is_empty());
    }

    #[test]
    fn rejects_unknown_fields_in_the_envelope() {
        let parsed = serde_json::from_value::<ResidentRequest>(json!({
            "guard_home": r"C:\Users\guard\.hol-guard",
            "state": {
                "schema": "windows-private-state.v1", "op": "ensure",
                "directory": r"C:\Users\guard\.hol-guard",
            },
            "extra": true,
        }));
        assert!(parsed.is_err());
    }
}
