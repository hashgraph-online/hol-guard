//! The desktop keyring Python's `keyring` library writes the policy-integrity
//! signing key to on Linux: its Secret Service backend
//! (`keyring/backends/SecretService.py`).
//!
//! Items are read and written the way that backend does, so a key either side
//! stores is the key the other reads: the default collection, searched by
//! `{"service", "username"}`, created with the same label and attributes and
//! `replace = true`, as `text/plain`. The session is DH-encrypted, as
//! `secretstorage` negotiates it when it can, so the key never crosses the
//! session bus in the clear.
//!
//! The runtime never answers a desktop prompt: a locked collection or item is
//! an error, which the mint answers `unavailable` for, and Python's own mint,
//! which may unlock it, runs instead.

use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Instant;

use secret_service::blocking::SecretService;
use secret_service::EncryptionType;

use super::mirrored::Primary;

/// `KeyringBackend.appid` for the Python library's own items.
const APPLICATION: &str = "Python keyring library";
/// `secretstorage`'s default content type for a stored secret.
const CONTENT_TYPE: &str = "text/plain";

/// The Secret Service items of one keyring service name. Every call must end
/// before `deadline`: a session bus that never answers is an error, so the
/// mint stays inside its caller's budget.
pub(super) struct SecretServiceKeyring {
    pub(super) service_name: String,
    pub(super) deadline: Instant,
}

fn attributes<'a>(service_name: &'a str, secret_id: &'a str) -> HashMap<&'a str, &'a str> {
    HashMap::from([("service", service_name), ("username", secret_id)])
}

impl SecretServiceKeyring {
    /// Run one D-Bus exchange on its own thread and give up at the deadline.
    /// A stalled thread is left to finish on its own; it holds no lock.
    fn bounded<T: Send + 'static>(
        &self,
        call: impl FnOnce() -> Result<T, ()> + Send + 'static,
    ) -> Result<T, ()> {
        let wait = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(())?;
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("hol-guard-keyring".to_owned())
            .spawn(move || {
                let _ = sender.send(call());
            })
            .map_err(|_| ())?;
        receiver.recv_timeout(wait).map_err(|_| ())?
    }
}

fn read(service_name: &str, secret_id: &str) -> Result<Option<String>, ()> {
    let service = SecretService::connect(EncryptionType::Dh).map_err(|_| ())?;
    let collection = service.get_default_collection().map_err(|_| ())?;
    if collection.is_locked().map_err(|_| ())? {
        return Err(());
    }
    let items = collection
        .search_items(attributes(service_name, secret_id))
        .map_err(|_| ())?;
    let Some(item) = items.first() else {
        return Ok(None);
    };
    if item.is_locked().map_err(|_| ())? {
        return Err(());
    }
    let value = String::from_utf8(item.get_secret().map_err(|_| ())?).map_err(|_| ())?;
    Ok((!value.is_empty()).then_some(value))
}

fn write(service_name: &str, secret_id: &str, value: &str) -> Result<(), ()> {
    let service = SecretService::connect(EncryptionType::Dh).map_err(|_| ())?;
    let collection = service.get_default_collection().map_err(|_| ())?;
    if collection.is_locked().map_err(|_| ())? {
        return Err(());
    }
    let label = format!("Password for '{secret_id}' on '{service_name}'");
    let mut item_attributes = attributes(service_name, secret_id);
    item_attributes.insert("application", APPLICATION);
    collection
        .create_item(
            &label,
            item_attributes,
            value.as_bytes(),
            true,
            CONTENT_TYPE,
        )
        .map(|_| ())
        .map_err(|_| ())
}

impl Primary for SecretServiceKeyring {
    fn get(&self, secret_id: &str) -> Result<Option<String>, ()> {
        let (service_name, secret_id) = (self.service_name.clone(), secret_id.to_owned());
        self.bounded(move || read(&service_name, &secret_id))
    }

    fn set(&self, secret_id: &str, value: &str) -> Result<(), ()> {
        let service_name = self.service_name.clone();
        let (secret_id, value) = (secret_id.to_owned(), value.to_owned());
        self.bounded(move || write(&service_name, &secret_id, &value))
    }
}
