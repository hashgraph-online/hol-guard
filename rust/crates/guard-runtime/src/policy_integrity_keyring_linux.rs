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
//! The runtime never unlocks anything: a locked collection or item is an
//! error, which the mint answers `unavailable` for, and Python's own mint,
//! which may unlock it, runs instead. A Secret Service that asks to confirm
//! the creation of an item gets the same prompt `secretstorage`'s
//! `create_item` raises in Python's mint, which this write replaces, and the
//! call still ends at the deadline. A write that ends that way, or whose
//! prompt lost its connection before answering, may yet commit, so the mint
//! then answers `busy` and Python mints nothing. The write's thread keeps the
//! mint lock until it settles, so no later mint, native or Python, can adopt a
//! fresh key that this write would then replace.

use std::collections::HashMap;
use std::fs::File;
use std::sync::mpsc;
use std::time::Instant;

use secret_service::blocking::SecretService;
use secret_service::EncryptionType;

use super::mirrored::{Existing, Primary, WriteFailure};

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
    /// A descriptor of the held mint lock. Each write's thread carries its
    /// own copy and closes it when the write settles, so a write that outlives
    /// the mint keeps the lock held until then.
    pub(super) mint_lock: Option<File>,
}

fn attributes<'a>(service_name: &'a str, secret_id: &'a str) -> HashMap<&'a str, &'a str> {
    HashMap::from([("service", service_name), ("username", secret_id)])
}

impl SecretServiceKeyring {
    /// Run one D-Bus exchange on its own thread and give up at the deadline.
    /// A stalled thread is left to finish on its own, holding `keep` until it
    /// does. A call that never started is [`WriteFailure::Refused`]; one that
    /// started and gave no answer in time is [`WriteFailure::Unsettled`].
    fn bounded<T: Send + 'static>(
        &self,
        keep: Option<File>,
        call: impl FnOnce() -> Result<T, WriteFailure> + Send + 'static,
    ) -> Result<T, WriteFailure> {
        let wait = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(WriteFailure::Refused)?;
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("hol-guard-keyring".to_owned())
            .spawn(move || {
                let answer = call();
                drop(keep);
                let _ = sender.send(answer);
            })
            .map_err(|_| WriteFailure::Refused)?;
        match receiver.recv_timeout(wait) {
            Ok(answer) => answer,
            Err(_) => Err(WriteFailure::Unsettled),
        }
    }
}

fn read(service_name: &str, secret_id: &str) -> Result<Option<String>, ()> {
    let service = SecretService::connect(EncryptionType::Dh).map_err(|_| ())?;
    read_from(&service, service_name, secret_id)
}

/// Read one item, telling a session bus with no Secret Service apart from a
/// service that could not give the item. Only a confirmed absence counts as
/// no service: no session bus, or a bus that says no one owns the Secret
/// Service name. A timeout, a failed session negotiation or a busy bus may
/// hide a keyring copy, so it reads as unreadable.
fn lookup(service_name: &str, secret_id: &str) -> Existing {
    let service = match SecretService::connect(EncryptionType::Dh) {
        Ok(service) => service,
        Err(error) => return connect_failure(&error),
    };
    match read_from(&service, service_name, secret_id) {
        Ok(Some(_)) => Existing::Present,
        Ok(None) => Existing::Absent,
        Err(()) => Existing::Unreadable,
    }
}

/// The bus's own answers for a name nobody owns: the session bus is up but
/// no Secret Service is registered on it.
const ABSENT_SERVICE_ERRORS: [&str; 2] = [
    "org.freedesktop.DBus.Error.ServiceUnknown",
    "org.freedesktop.DBus.Error.NameHasNoOwner",
];

fn connect_failure(error: &secret_service::Error) -> Existing {
    use secret_service::Error as Service;
    use zbus::fdo::Error as Fdo;
    let absent = match error {
        Service::Unavailable => true,
        Service::ZbusFdo(Fdo::ServiceUnknown(_) | Fdo::NameHasNoOwner(_)) => true,
        Service::Zbus(zbus::Error::FDO(fdo)) => {
            matches!(**fdo, Fdo::ServiceUnknown(_) | Fdo::NameHasNoOwner(_))
        }
        Service::Zbus(zbus::Error::MethodError(name, _, _)) => {
            ABSENT_SERVICE_ERRORS.contains(&name.as_str())
        }
        _ => false,
    };
    if absent {
        Existing::NoService
    } else {
        Existing::Unreadable
    }
}

fn read_from(
    service: &SecretService<'_>,
    service_name: &str,
    secret_id: &str,
) -> Result<Option<String>, ()> {
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

/// A failure before the item is submitted, which nothing can commit.
fn refused<E>(_: E) -> WriteFailure {
    WriteFailure::Refused
}

/// How a submitted `CreateItem` failed. A prompt whose connection closed
/// before it answered left the outcome unknown; a dismissed prompt, or any
/// other error the service reports, created nothing.
fn create_failure(error: &secret_service::Error) -> WriteFailure {
    match error {
        secret_service::Error::PromptDisconnected => WriteFailure::Unsettled,
        _ => WriteFailure::Refused,
    }
}

fn write(service_name: &str, secret_id: &str, value: &str) -> Result<(), WriteFailure> {
    let service = SecretService::connect(EncryptionType::Dh).map_err(refused)?;
    let collection = service.get_default_collection().map_err(refused)?;
    if collection.is_locked().map_err(refused)? {
        return Err(WriteFailure::Refused);
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
        .map_err(|error| create_failure(&error))
}

impl SecretServiceKeyring {
    /// What the keyring holds for `secret_id`, within the deadline. A
    /// service that does not answer in time is unreadable, not absent.
    pub(super) fn existing(&self, secret_id: &str) -> Existing {
        let (service_name, secret_id) = (self.service_name.clone(), secret_id.to_owned());
        self.bounded(None, move || Ok(lookup(&service_name, &secret_id)))
            .unwrap_or(Existing::Unreadable)
    }
}

impl Primary for SecretServiceKeyring {
    fn get(&self, secret_id: &str) -> Result<Option<String>, ()> {
        let (service_name, secret_id) = (self.service_name.clone(), secret_id.to_owned());
        self.bounded(None, move || {
            read(&service_name, &secret_id).map_err(|()| WriteFailure::Refused)
        })
        .map_err(|_| ())
    }

    fn set(&self, secret_id: &str, value: &str) -> Result<(), WriteFailure> {
        let service_name = self.service_name.clone();
        let (secret_id, value) = (secret_id.to_owned(), value.to_owned());
        // A write never starts without a copy of the mint lock to outlive it.
        let keep = match &self.mint_lock {
            Some(lock) => Some(lock.try_clone().map_err(refused)?),
            None => None,
        };
        self.bounded(keep, move || write(&service_name, &secret_id, &value))
    }
}

#[cfg(test)]
mod tests {
    use super::{connect_failure, Existing};

    #[test]
    fn only_a_confirmed_absent_service_counts_as_no_keyring() {
        assert!(matches!(
            connect_failure(&secret_service::Error::Unavailable),
            Existing::NoService
        ));
        for error in [
            zbus::fdo::Error::ServiceUnknown("org.freedesktop.secrets".to_owned()),
            zbus::fdo::Error::NameHasNoOwner("org.freedesktop.secrets".to_owned()),
        ] {
            assert!(matches!(
                connect_failure(&secret_service::Error::ZbusFdo(error.clone())),
                Existing::NoService
            ));
            assert!(matches!(
                connect_failure(&secret_service::Error::Zbus(zbus::Error::FDO(Box::new(
                    error
                )))),
                Existing::NoService
            ));
        }
        assert!(matches!(
            connect_failure(&secret_service::Error::ZbusFdo(zbus::fdo::Error::TimedOut(
                "bus busy".to_owned()
            ))),
            Existing::Unreadable
        ));
        for error in [
            secret_service::Error::Crypto("negotiation failed"),
            secret_service::Error::Locked,
            secret_service::Error::PromptDisconnected,
        ] {
            assert!(matches!(connect_failure(&error), Existing::Unreadable));
        }
    }
}
