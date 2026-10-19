//! In-memory passphrase cache with a fixed expiry.
//!
//! Keyed by the certificate's fingerprint. Entries are wiped on drop and
//! expire `ttl` after they were typed (a later use does not extend them).
//! A TTL of zero turns caching off.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

struct Entry {
    passphrase: Zeroizing<String>,
    stored_at: Instant,
}

struct Inner {
    entries: HashMap<String, Entry>,
    ttl: Duration,
}

pub struct PassphraseCache {
    inner: Mutex<Inner>,
}

impl PassphraseCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self { inner: Mutex::new(Inner { entries: HashMap::new(), ttl: Duration::from_secs(ttl_secs) }) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock must not keep secrets alive: take it anyway.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Changes the lifetime of future lookups; zero disables and empties the cache.
    pub fn set_ttl(&self, secs: u64) {
        let mut inner = self.lock();
        inner.ttl = Duration::from_secs(secs);
        if secs == 0 {
            inner.entries.clear();
        }
    }

    pub fn store(&self, fingerprint: &str, passphrase: &str) {
        let mut inner = self.lock();
        if inner.ttl.is_zero() {
            return;
        }
        let ttl = inner.ttl;
        inner.entries.retain(|_, e| e.stored_at.elapsed() < ttl);
        inner.entries.insert(
            fingerprint.to_uppercase(),
            Entry { passphrase: Zeroizing::new(passphrase.to_string()), stored_at: Instant::now() },
        );
    }

    pub fn get(&self, fingerprint: &str) -> Option<Zeroizing<String>> {
        let inner = self.lock();
        inner
            .entries
            .get(&fingerprint.to_uppercase())
            .filter(|e| e.stored_at.elapsed() < inner.ttl)
            .map(|e| e.passphrase.clone())
    }

    /// Every live entry, for operations where the key is only known later (decrypt).
    pub fn snapshot(&self) -> HashMap<String, Zeroizing<String>> {
        let inner = self.lock();
        inner
            .entries
            .iter()
            .filter(|(_, e)| e.stored_at.elapsed() < inner.ttl)
            .map(|(fp, e)| (fp.clone(), e.passphrase.clone()))
            .collect()
    }

    pub fn forget(&self, fingerprint: &str) {
        self.lock().entries.remove(&fingerprint.to_uppercase());
    }

    pub fn clear(&self) {
        self.lock().entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_and_expires() {
        let c = PassphraseCache::new(60);
        c.store("abcd", "pw");
        assert_eq!(c.get("ABCD").as_deref().map(String::as_str), Some("pw"));
        assert_eq!(c.snapshot().len(), 1);
        c.forget("abcd");
        assert!(c.get("abcd").is_none());

        let short = PassphraseCache::new(1);
        short.store("k", "pw");
        std::thread::sleep(Duration::from_millis(1100));
        assert!(short.get("k").is_none());
        assert!(short.snapshot().is_empty());
    }

    #[test]
    fn zero_ttl_disables_and_clears() {
        let c = PassphraseCache::new(60);
        c.store("k", "pw");
        c.set_ttl(0);
        assert!(c.get("k").is_none());
        c.store("k", "pw");
        assert!(c.get("k").is_none());
    }
}
