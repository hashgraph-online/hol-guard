use std::cell::RefCell;
use std::collections::BTreeMap;

use serde_json::json;

use super::*;

const HOME: &str = r"C:\Users\guard\.hol-guard";
const STATE: &str = r"C:\Users\guard\.hol-guard\native-runtime";

/// Files as a fake Windows keeps them, keyed by folded directory and name,
/// plus every call the answers made.
#[derive(Default)]
struct FakeStore {
    files: RefCell<BTreeMap<(String, String), Vec<u8>>>,
    calls: RefCell<Vec<String>>,
    failure: Option<&'static str>,
}

impl PrivateStore for FakeStore {
    fn read(
        &self,
        directory: &str,
        name: &str,
        maximum_bytes: u64,
        private_root: Option<&str>,
    ) -> Result<Option<Vec<u8>>, String> {
        self.calls.borrow_mut().push(format!(
            "read {directory} {name} {maximum_bytes} {private_root:?}"
        ));
        if let Some(code) = self.failure {
            return Err(code.to_owned());
        }
        Ok(self
            .files
            .borrow()
            .get(&(fold(directory), name.to_owned()))
            .cloned())
    }

    fn write(
        &self,
        directory: &str,
        name: &str,
        content: &[u8],
        private_root: &str,
    ) -> Result<(), String> {
        self.calls
            .borrow_mut()
            .push(format!("write {directory} {name} {private_root}"));
        if let Some(code) = self.failure {
            return Err(code.to_owned());
        }
        self.files
            .borrow_mut()
            .insert((fold(directory), name.to_owned()), content.to_vec());
        Ok(())
    }

    fn delete(&self, directory: &str, name: &str, private_root: &str) -> Result<bool, String> {
        self.calls
            .borrow_mut()
            .push(format!("delete {directory} {name} {private_root}"));
        if let Some(code) = self.failure {
            return Err(code.to_owned());
        }
        Ok(self
            .files
            .borrow_mut()
            .remove(&(fold(directory), name.to_owned()))
            .is_some())
    }

    fn ensure(&self, directory: &str, private_root: &str) -> Result<(), String> {
        self.calls
            .borrow_mut()
            .push(format!("ensure {directory} {private_root}"));
        match self.failure {
            Some(code) => Err(code.to_owned()),
            None => Ok(()),
        }
    }
}

fn ask(store: &FakeStore, request: Value) -> Result<Value, String> {
    let mut request = request;
    request["schema"] = json!(SCHEMA);
    let request: Request = serde_json::from_value(request).map_err(|_| invalid())?;
    answer(&request, store)
}

fn encoded(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn written_state_reads_back_and_deletes() {
    let store = FakeStore::default();
    assert_eq!(
        ask(
            &store,
            json!({
                "op": "write",
                "directory": STATE,
                "name": "authority.json",
                "private_root": HOME,
                "maximum_bytes": 16,
                "content_b64": encoded(b"{\"v\":1}"),
            })
        ),
        Ok(json!({"written": true}))
    );
    let read = json!({
        "op": "read",
        "directory": STATE,
        "name": "authority.json",
        "private_root": HOME,
        "maximum_bytes": 16,
    });
    assert_eq!(
        ask(&store, read.clone()),
        Ok(json!({"content_b64": encoded(b"{\"v\":1}")}))
    );
    let delete = json!({"op": "delete", "directory": STATE, "name": "authority.json"});
    assert_eq!(ask(&store, delete.clone()), Ok(json!({"deleted": true})));
    assert_eq!(ask(&store, delete), Ok(json!({"deleted": false})));
    assert_eq!(ask(&store, read), Ok(json!({"content_b64": null})));
    assert_eq!(
        *store.calls.borrow(),
        vec![
            format!("write {STATE} authority.json {HOME}"),
            format!(
                "read {STATE} authority.json 16 Some(\"{}\")",
                HOME.replace('\\', r"\\")
            ),
            // Without a private root, a writer or deleter is bound to the
            // directory itself and a reader only holds it.
            format!("delete {STATE} authority.json {STATE}"),
            format!("delete {STATE} authority.json {STATE}"),
            format!(
                "read {STATE} authority.json 16 Some(\"{}\")",
                HOME.replace('\\', r"\\")
            ),
        ]
    );
    store.calls.borrow_mut().clear();
    assert_eq!(
        ask(
            &store,
            json!({"op": "read", "directory": STATE, "name": "x", "maximum_bytes": 1})
        ),
        Ok(json!({"content_b64": null}))
    );
    assert_eq!(
        *store.calls.borrow(),
        vec![format!("read {STATE} x 1 None")]
    );
}

#[test]
fn ensure_binds_from_the_private_root() {
    let store = FakeStore::default();
    assert_eq!(
        ask(&store, json!({"op": "ensure", "directory": STATE})),
        Ok(json!({"ensured": true}))
    );
    assert_eq!(
        ask(
            &store,
            json!({"op": "ensure", "directory": STATE, "private_root": HOME})
        ),
        Ok(json!({"ensured": true}))
    );
    assert_eq!(
        *store.calls.borrow(),
        vec![
            format!("ensure {STATE} {STATE}"),
            format!("ensure {STATE} {HOME}"),
        ]
    );
    for extra in [
        json!({"name": "a"}),
        json!({"maximum_bytes": 4}),
        json!({"content_b64": "YQ=="}),
    ] {
        let mut request = json!({"op": "ensure", "directory": STATE});
        for (key, value) in extra.as_object().unwrap() {
            request[key] = value.clone();
        }
        assert_eq!(ask(&store, request), Err(invalid()));
    }
    assert_eq!(
        ask(
            &store,
            json!({"op": "ensure", "directory": HOME, "private_root": STATE})
        ),
        Err(invalid())
    );
    assert_eq!(
        ask(
            &store,
            json!({"op": "read", "directory": STATE, "maximum_bytes": 4})
        ),
        Err(invalid())
    );
    assert_eq!(store.calls.borrow().len(), 2);
}

#[test]
fn operational_failures_answer_their_code() {
    let store = FakeStore {
        failure: Some("native_resident_windows_access_denied"),
        ..FakeStore::default()
    };
    for request in [
        json!({"op": "read", "directory": STATE, "name": "a", "maximum_bytes": 4}),
        json!({
            "op": "write",
            "directory": STATE,
            "name": "a",
            "maximum_bytes": 4,
            "content_b64": encoded(b"ab"),
        }),
        json!({"op": "delete", "directory": STATE, "name": "a"}),
        json!({"op": "ensure", "directory": STATE}),
    ] {
        assert_eq!(
            ask(&store, request),
            Ok(json!({"error": "native_resident_windows_access_denied"}))
        );
    }
}

#[test]
fn reads_refuse_empty_and_oversized_content() {
    let store = FakeStore::default();
    for content in [Vec::new(), b"12345".to_vec()] {
        store
            .files
            .borrow_mut()
            .insert((fold(STATE), "a".to_owned()), content);
        assert_eq!(
            ask(
                &store,
                json!({"op": "read", "directory": STATE, "name": "a", "maximum_bytes": 4})
            ),
            Ok(json!({"error": "native_windows_private_state_invalid"}))
        );
    }
}

#[test]
fn writes_need_content_inside_their_bound() {
    let store = FakeStore::default();
    let write = |content: Option<&str>, maximum_bytes: Value| {
        let mut request = json!({
            "op": "write",
            "directory": STATE,
            "name": "a",
            "maximum_bytes": maximum_bytes,
        });
        if let Some(content) = content {
            request["content_b64"] = json!(content);
        }
        ask(&store, request)
    };
    let three = encoded(b"abc");
    assert!(write(Some(&three), json!(3)).is_ok());
    assert_eq!(write(Some(&three), json!(2)), Err(invalid()));
    assert_eq!(write(Some(""), json!(3)), Err(invalid()));
    assert_eq!(write(Some("not base64!"), json!(3)), Err(invalid()));
    assert_eq!(write(None, json!(3)), Err(invalid()));
    assert_eq!(write(Some(&three), json!(0)), Err(invalid()));
    assert_eq!(
        write(Some(&three), json!(MAX_CONTENT_BYTES + 1)),
        Err(invalid())
    );
    assert_eq!(write(Some(&three), Value::Null), Err(invalid()));
}

#[test]
fn paths_and_names_are_checked() {
    let store = FakeStore::default();
    let read = |directory: &str, name: &str, private_root: Option<&str>| {
        let mut request = json!({
            "op": "read",
            "directory": directory,
            "name": name,
            "maximum_bytes": 4,
        });
        if let Some(root) = private_root {
            request["private_root"] = json!(root);
        }
        ask(&store, request)
    };
    assert!(read(STATE, "a", Some(HOME)).is_ok());
    assert!(read(STATE, "a", Some(STATE)).is_ok());
    assert!(read(r"\\server\share\state", "a", None).is_ok());
    assert!(read("C:/Users/guard/.hol-guard/native-runtime", "a", Some(HOME)).is_ok());
    assert!(read(
        r"c:\users\GUARD\.hol-guard\native-runtime\",
        "a",
        Some(HOME)
    )
    .is_ok());
    for (directory, name, root) in [
        (r"Users\guard", "a", None),
        ("C:state", "a", None),
        (r"C:\Users\guard\..\other", "a", None),
        (r"C:\Users\guard\.\state", "a", None),
        (STATE, "", None),
        (STATE, ".", None),
        (STATE, "..", None),
        (STATE, r"x\y", None),
        (STATE, "x/y", None),
        (STATE, "a:stream", None),
        (STATE, "a\0b", None),
        (STATE, "a", Some(r"C:\Users\other")),
        (STATE, "a", Some(r"C:\Users\guard\.hol-guard\native")),
        (HOME, "a", Some(STATE)),
        (STATE, "a", Some("relative")),
    ] {
        assert_eq!(
            read(directory, name, root),
            Err(invalid()),
            "{directory} {name:?} {root:?}"
        );
    }
    assert_eq!(
        read(STATE, &"a".repeat(MAX_NAME_CHARS + 1), None),
        Err(invalid())
    );
    assert_eq!(store.calls.borrow().len(), 5);
}

#[test]
fn requests_are_checked() {
    let store = FakeStore::default();
    assert!(ask(
        &store,
        json!({"op": "list", "directory": STATE, "name": "a"})
    )
    .is_err());
    assert!(ask(
        &store,
        json!({"op": "read", "directory": STATE, "name": "a", "maximum_bytes": 4, "content_b64": "YQ=="})
    )
    .is_err());
    assert!(ask(
        &store,
        json!({"op": "delete", "directory": STATE, "name": "a", "maximum_bytes": 4})
    )
    .is_err());
    assert!(answer(
        &serde_json::from_value(json!({
            "schema": "other",
            "op": "delete",
            "directory": STATE,
            "name": "a",
        }))
        .unwrap(),
        &store
    )
    .is_err());
    assert!(serde_json::from_value::<Request>(json!({
        "schema": SCHEMA,
        "op": "delete",
        "directory": STATE,
        "name": "a",
        "extra": true,
    }))
    .is_err());
    assert!(store.calls.borrow().is_empty());
    assert!(run_command(&b"{"[..]).is_err());
    let oversized = vec![b' '; MAX_REQUEST_BYTES as usize + 1];
    assert_eq!(
        run_command(&oversized[..]),
        Err("windows_private_state_request_too_large".to_owned())
    );
}

#[cfg(not(windows))]
#[test]
fn off_windows_nothing_is_touched() {
    let response = run_command(
        json!({
            "schema": SCHEMA,
            "op": "delete",
            "directory": STATE,
            "name": "a",
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&response).unwrap(),
        json!({"error": "native_windows_private_state_unsupported"})
    );
}

#[cfg(windows)]
#[test]
fn private_state_round_trips_on_windows() {
    let home = std::env::temp_dir().join(format!(
        "hol-guard-private-state-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    std::fs::create_dir_all(&home).unwrap();
    let home_text = home.to_str().unwrap().to_owned();
    let state = home.join("native-runtime");
    let state_text = state.to_str().unwrap().to_owned();
    let store = SystemStore;
    assert_eq!(store.read(&state_text, "a.json", 64, None), Ok(None));
    assert_eq!(
        store.read(&state_text, "a.json", 64, Some(&home_text)),
        Ok(None)
    );
    store
        .write(&state_text, "a.json", b"first", &home_text)
        .unwrap();
    store
        .write(&state_text, "a.json", b"second", &home_text)
        .unwrap();
    assert_eq!(
        store.read(&state_text, "a.json", 64, None),
        Ok(Some(b"second".to_vec()))
    );
    assert_eq!(
        store.read(&state_text, "a.json", 64, Some(&home_text)),
        Ok(Some(b"second".to_vec()))
    );
    assert!(store.read(&state_text, "a.json", 3, None).is_err());
    // Only the committed file is left behind.
    let names: Vec<_> = std::fs::read_dir(&state)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, vec![std::ffi::OsString::from("a.json")]);
    assert_eq!(store.delete(&state_text, "a.json", &home_text), Ok(true));
    assert_eq!(store.delete(&state_text, "a.json", &home_text), Ok(false));
    assert_eq!(
        store.delete(
            &home.join("missing").to_string_lossy(),
            "a.json",
            &home_text
        ),
        Ok(false)
    );
    // Missing ancestors above the private root are created private too.
    let nested = home.join("missing").join("deeper").join("state");
    let nested_text = nested.to_str().unwrap().to_owned();
    assert_eq!(store.ensure(&nested_text, &nested_text), Ok(()));
    assert!(nested.is_dir());
    assert_eq!(store.ensure(&state_text, &home_text), Ok(()));
    let _ = std::fs::remove_dir_all(&home);
}
