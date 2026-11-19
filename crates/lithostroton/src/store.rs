//! lithostroton's own state: registered clients, sign-in requests in progress, codes,
//! browser sessions. Users, devices and tokens are the host's ([`crate::Host`]); this is the
//! rest.
//!
//! The [`Store`] is a small key-value interface so that a host can keep it in its own
//! database with one table:
//!
//! ```sql
//! CREATE TABLE lithostroton_store (
//!     kind       TEXT NOT NULL,
//!     key        TEXT NOT NULL,
//!     value      BYTEA NOT NULL,
//!     expires_at TIMESTAMPTZ,          -- NULL: kept until deleted
//!     PRIMARY KEY (kind, key)
//! );
//! ```
//!
//! Keys of entries that stand for a secret (an authorization code, a device code, a browser
//! session) are a SHA-256 digest of it: the store never holds a working secret.
//!
//! The kinds lithostroton uses, and how long their entries live:
//!
//! | kind              | what                                         | lives               |
//! |-------------------|----------------------------------------------|---------------------|
//! | `client`          | a registered client's metadata               | until deleted       |
//! | `client_digest`   | client ID by digest of its metadata          | until deleted       |
//! | `browser_session` | a signed-in browser                          | browser session ttl |
//! | `browser_epoch`   | per user: sessions older than this are ended | browser session ttl |
//! | `authorization`   | an authorization request awaiting the user  | 30 minutes          |
//! | `code`            | an authorization code                        | code ttl            |
//! | `code_used`       | a code that was exchanged (replay detection) | code ttl            |
//! | `device_grant`    | a device authorization request               | device code ttl     |
//! | `user_code`       | device grant by user code                    | device code ttl     |
//!
//! `client` and `client_digest` must survive a restart (clients keep their client ID);
//! the others may be lost on a restart at the cost of sign-ins in progress and browser
//! sessions.
//!
//! [`MemoryStore`] keeps everything in memory.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};

use crate::clock::Clock;

/// Why the store could not do what was asked.
#[derive(Debug, thiserror::Error)]
#[error("store: {0}")]
pub struct StoreError(pub String);

/// Key-value storage with expiry. An entry whose `expires_at` has passed is absent for every
/// operation (whether or not it has been removed yet). Every operation is atomic.
#[async_trait]
pub trait Store: Send + Sync + 'static {
    /// Adds an entry if there is no live entry under `(kind, key)`. Returns whether it was
    /// added.
    async fn insert(
        &self,
        kind: &str,
        key: &str,
        value: &[u8],
        expires_at: Option<SystemTime>,
    ) -> Result<bool, StoreError>;

    /// The value of the live entry under `(kind, key)`.
    async fn get(&self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, StoreError>;

    /// Replaces the value and expiry of the live entry under `(kind, key)` if its value is
    /// `expected`, byte for byte. Returns whether it was replaced.
    async fn replace(
        &self,
        kind: &str,
        key: &str,
        expected: &[u8],
        value: &[u8],
        expires_at: Option<SystemTime>,
    ) -> Result<bool, StoreError>;

    /// Removes the entry under `(kind, key)` and returns its value if it was live. Of two
    /// concurrent takes of one entry, one gets the value.
    async fn take(&self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, StoreError>;

    /// Removes the entry under `(kind, key)`, if any.
    async fn delete(&self, kind: &str, key: &str) -> Result<(), StoreError>;

    /// Removes expired entries. lithostroton calls this every few minutes; a store that
    /// removes them by itself can leave it as it is.
    async fn purge_expired(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

type Entries = HashMap<(String, String), (Vec<u8>, Option<SystemTime>)>;

/// A [`Store`] in memory: everything is lost when the process ends.
pub struct MemoryStore {
    clock: Clock,
    entries: Mutex<Entries>,
}

impl MemoryStore {
    pub fn new() -> MemoryStore {
        MemoryStore::with_clock(Clock::system())
    }

    pub fn with_clock(clock: Clock) -> MemoryStore {
        MemoryStore {
            clock,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// How many entries of `kind` are live.
    pub fn count(&self, kind: &str) -> usize {
        let now = self.clock.now();
        self.lock()
            .iter()
            .filter(|((k, _), (_, exp))| k == kind && live(*exp, now))
            .count()
    }

    /// The keys of the live entries of `kind`.
    pub fn keys(&self, kind: &str) -> Vec<String> {
        let now = self.clock.now();
        self.lock()
            .iter()
            .filter(|((k, _), (_, exp))| k == kind && live(*exp, now))
            .map(|((_, key), _)| key.clone())
            .collect()
    }

    /// Every live value, for tests that look for what must not be stored.
    pub fn dump(&self) -> Vec<(String, String, Vec<u8>)> {
        let now = self.clock.now();
        self.lock()
            .iter()
            .filter(|(_, (_, exp))| live(*exp, now))
            .map(|((kind, key), (value, _))| (kind.clone(), key.clone(), value.clone()))
            .collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Entries> {
        // A panic while the lock was held cannot leave a half-made entry: every change is
        // one map operation.
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for MemoryStore {
    fn default() -> MemoryStore {
        MemoryStore::new()
    }
}

fn live(expires_at: Option<SystemTime>, now: SystemTime) -> bool {
    expires_at.is_none_or(|exp| exp > now)
}

#[async_trait]
impl Store for MemoryStore {
    async fn insert(
        &self,
        kind: &str,
        key: &str,
        value: &[u8],
        expires_at: Option<SystemTime>,
    ) -> Result<bool, StoreError> {
        let now = self.clock.now();
        let mut entries = self.lock();
        let k = (kind.to_owned(), key.to_owned());
        if entries.get(&k).is_some_and(|(_, exp)| live(*exp, now)) {
            return Ok(false);
        }
        entries.insert(k, (value.to_vec(), expires_at));
        Ok(true)
    }

    async fn get(&self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let now = self.clock.now();
        Ok(self
            .lock()
            .get(&(kind.to_owned(), key.to_owned()))
            .filter(|(_, exp)| live(*exp, now))
            .map(|(v, _)| v.clone()))
    }

    async fn replace(
        &self,
        kind: &str,
        key: &str,
        expected: &[u8],
        value: &[u8],
        expires_at: Option<SystemTime>,
    ) -> Result<bool, StoreError> {
        let now = self.clock.now();
        let mut entries = self.lock();
        match entries.get_mut(&(kind.to_owned(), key.to_owned())) {
            Some((v, exp)) if live(*exp, now) && v.as_slice() == expected => {
                *v = value.to_vec();
                *exp = expires_at;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn take(&self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let now = self.clock.now();
        Ok(self
            .lock()
            .remove(&(kind.to_owned(), key.to_owned()))
            .filter(|(_, exp)| live(*exp, now))
            .map(|(v, _)| v))
    }

    async fn delete(&self, kind: &str, key: &str) -> Result<(), StoreError> {
        self.lock().remove(&(kind.to_owned(), key.to_owned()));
        Ok(())
    }

    async fn purge_expired(&self) -> Result<(), StoreError> {
        let now = self.clock.now();
        self.lock().retain(|_, (_, exp)| live(*exp, now));
        Ok(())
    }
}

/// The store with JSON values: what the rest of lithostroton uses.
#[derive(Clone)]
pub(crate) struct Typed(pub Arc<dyn Store>);

/// A value read from the store, with the bytes it was read from, for a later
/// [`Typed::replace`].
pub(crate) struct Read<T> {
    pub value: T,
    pub raw: Vec<u8>,
}

impl Typed {
    pub async fn insert<T: Serialize>(
        &self,
        kind: &str,
        key: &str,
        value: &T,
        expires_at: Option<SystemTime>,
    ) -> Result<bool, StoreError> {
        self.0.insert(kind, key, &encode(value)?, expires_at).await
    }

    pub async fn get<T: DeserializeOwned>(
        &self,
        kind: &str,
        key: &str,
    ) -> Result<Option<Read<T>>, StoreError> {
        match self.0.get(kind, key).await? {
            Some(raw) => Ok(decode(kind, &raw).map(|value| Read { value, raw })),
            None => Ok(None),
        }
    }

    pub async fn replace<T: Serialize>(
        &self,
        kind: &str,
        key: &str,
        old: &[u8],
        value: &T,
        expires_at: Option<SystemTime>,
    ) -> Result<bool, StoreError> {
        self.0
            .replace(kind, key, old, &encode(value)?, expires_at)
            .await
    }

    pub async fn take<T: DeserializeOwned>(
        &self,
        kind: &str,
        key: &str,
    ) -> Result<Option<T>, StoreError> {
        Ok(self
            .0
            .take(kind, key)
            .await?
            .and_then(|raw| decode(kind, &raw)))
    }

    pub async fn delete(&self, kind: &str, key: &str) -> Result<(), StoreError> {
        self.0.delete(kind, key).await
    }
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(value).map_err(|e| StoreError(format!("encoding: {e}")))
}

/// An entry that does not decode (written by a later version, or damaged) counts as absent.
fn decode<T: DeserializeOwned>(kind: &str, raw: &[u8]) -> Option<T> {
    match serde_json::from_slice(raw) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(kind, error = %e, "an entry of the store does not decode, ignored");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn block<F: std::future::Future>(f: F) -> F::Output {
        #[allow(clippy::unwrap_used)]
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn memory_store_semantics() {
        block(async {
            let now = Arc::new(Mutex::new(
                SystemTime::UNIX_EPOCH + Duration::from_secs(1000),
            ));
            let n = now.clone();
            let store = MemoryStore::with_clock(Clock::from_fn(move || *n.lock().unwrap()));
            let soon = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1010));

            assert!(store.insert("k", "a", b"1", soon).await.unwrap());
            assert!(!store.insert("k", "a", b"2", None).await.unwrap());
            assert_eq!(
                store.get("k", "a").await.unwrap().as_deref(),
                Some(&b"1"[..])
            );
            assert!(!store.replace("k", "a", b"x", b"3", soon).await.unwrap());
            assert!(store.replace("k", "a", b"1", b"3", soon).await.unwrap());
            assert_eq!(
                store.take("k", "a").await.unwrap().as_deref(),
                Some(&b"3"[..])
            );
            assert_eq!(store.take("k", "a").await.unwrap(), None);

            // expiry: absent once the time has come, and the key can be used again
            assert!(store.insert("k", "b", b"1", soon).await.unwrap());
            *now.lock().unwrap() = SystemTime::UNIX_EPOCH + Duration::from_secs(1010);
            assert_eq!(store.get("k", "b").await.unwrap(), None);
            assert!(!store.replace("k", "b", b"1", b"2", None).await.unwrap());
            assert!(store.insert("k", "b", b"2", None).await.unwrap());
            store.purge_expired().await.unwrap();
            assert_eq!(store.count("k"), 1);
        });
    }
}
